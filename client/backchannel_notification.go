package client

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
)

// maxBackchannelNotificationBytes bounds a ping callback's body, which
// carries only an auth_req_id.
const maxBackchannelNotificationBytes = 4096

// BackchannelNotification is a CIBA ping callback (§10.2): the
// authorization server telling a client registered for ping delivery
// that it has a decision for one auth_req_id. It is not yet
// authenticated — check it with Authenticates before acting on it.
type BackchannelNotification struct {
	authReqID string
	token     string
}

// AuthReqID is the auth_req_id the notification is about: the key for
// looking up the BackchannelAuthenticationSession it belongs to.
func (n BackchannelNotification) AuthReqID() string { return n.authReqID }

// Authenticates reports whether n was sent for session: it names
// session's auth_req_id, and carries, as its bearer token, the
// client_notification_token this client sent with that request
// (compared in constant time). CIBA §10.2 requires this check before a
// notification is trusted; when it fails, respond 401 Unauthorized, as
// §10.2 has a client do when the bearer token is not valid. A
// notification carrying no bearer token, or not exactly one, never
// authenticates.
// When it passes, respond 204 No Content, then collect the decision with
// PollBackchannelAuthentication — after responding, so the server isn't
// kept waiting. It is always false for a session begun under poll
// delivery, which has no notification token.
func (n BackchannelNotification) Authenticates(session BackchannelAuthenticationSession) bool {
	if n.token == "" || session.notificationToken == "" || n.authReqID != session.authReqID {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(n.token), []byte(session.notificationToken)) == 1
}

// ParseBackchannelNotification reads a CIBA ping callback (§10.2) from
// r, a request to this client's notification endpoint: a POST with the
// client_notification_token as a bearer token and a JSON body naming the
// auth_req_id. Members of the body other than auth_req_id are ignored,
// as §10.2 requires. It reads at most a few kilobytes of body.
//
// A request that isn't a well-formed ping returns an ErrorInvalidRequest
// *Error; respond 400 Bad Request. A well-formed one isn't yet trusted:
// see BackchannelNotification.Authenticates, which refuses one without
// exactly one bearer token, so that it is answered 401 Unauthorized as
// CIBA §10.2 asks.
func ParseBackchannelNotification(r *http.Request) (BackchannelNotification, error) {
	if r.Method != http.MethodPost {
		return BackchannelNotification{}, newError(ErrorInvalidRequest, "a backchannel notification must be a POST", nil)
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || !strings.EqualFold(mediaType, "application/json") {
		return BackchannelNotification{}, newError(ErrorInvalidRequest, "a backchannel notification must be application/json", err)
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBackchannelNotificationBytes+1))
	if err != nil {
		return BackchannelNotification{}, newError(ErrorInvalidRequest, "could not read the backchannel notification", err)
	}
	if len(body) > maxBackchannelNotificationBytes {
		return BackchannelNotification{}, newError(ErrorInvalidRequest, "the backchannel notification is too large", nil)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(body, &members); err != nil {
		return BackchannelNotification{}, newError(ErrorInvalidRequest, "the backchannel notification is not a JSON object", err)
	}
	var authReqID string
	if raw, ok := members["auth_req_id"]; !ok || json.Unmarshal(raw, &authReqID) != nil || authReqID == "" {
		return BackchannelNotification{}, newError(ErrorInvalidRequest, "the backchannel notification has no auth_req_id", errors.New("auth_req_id missing, empty or not a string"))
	}
	return BackchannelNotification{authReqID: authReqID, token: bearerToken(r.Header)}, nil
}

// bearerToken returns the request's bearer token, or "" (which never
// authenticates) unless it has exactly one Authorization header with
// the Bearer scheme and a non-empty token.
func bearerToken(h http.Header) string {
	if len(h.Values("Authorization")) != 1 {
		return ""
	}
	scheme, token, ok := strings.Cut(h.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return token
}

package client

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// backchannelSessionVersion prefixes every encoded
// BackchannelAuthenticationSession, so a later format can be told apart.
const backchannelSessionVersion = "v1."

// maxEncodedBackchannelSession bounds what ParseBackchannelAuthenticationSession
// reads: an auth_req_id and a notification token, with room to spare.
const maxEncodedBackchannelSession = 4096

// encodedBackchannelSession is the JSON inside an encoded session.
type encodedBackchannelSession struct {
	AuthReqID         string    `json:"a"`
	IntervalMillis    int64     `json:"i"`
	ExpiresAt         time.Time `json:"e"`
	NotificationToken string    `json:"n,omitempty"`
	// OpenID: whether the request's scope included "openid". Absent in a
	// session encoded before it existed, which then reads as false.
	OpenID bool `json:"o,omitempty"`
}

// MarshalText encodes s for storage, so a session begun on one instance
// can be polled, or its ping callback authenticated, on another: store
// the encoding keyed by AuthReqID, and restore it with
// ParseBackchannelAuthenticationSession (or UnmarshalText).
//
// The encoding is opaque and versioned, and it contains the
// client_notification_token: store it as you would a credential, and
// don't log it. It carries no integrity protection and needs none:
// every result still comes from the authorization server, for this
// client's own auth_req_id, so a modified session can at most make the
// client poll for another of its own requests.
func (s BackchannelAuthenticationSession) MarshalText() ([]byte, error) {
	if s.authReqID == "" {
		return nil, newError(ErrorInvalidRequest, "a backchannel authentication session without an auth_req_id can't be encoded", nil)
	}
	raw, err := json.Marshal(encodedBackchannelSession{
		AuthReqID: s.authReqID, IntervalMillis: s.interval.Milliseconds(),
		ExpiresAt: s.expiresAt.UTC(), NotificationToken: s.notificationToken,
		OpenID: s.openID,
	})
	if err != nil {
		return nil, newError(ErrorInternal, "failed to encode the backchannel authentication session", err)
	}
	return []byte(backchannelSessionVersion + base64.RawURLEncoding.EncodeToString(raw)), nil
}

// UnmarshalText restores a session MarshalText encoded — see
// ParseBackchannelAuthenticationSession.
func (s *BackchannelAuthenticationSession) UnmarshalText(text []byte) error {
	parsed, err := ParseBackchannelAuthenticationSession(string(text))
	if err != nil {
		return err
	}
	*s = parsed
	return nil
}

// ParseBackchannelAuthenticationSession restores a session
// BackchannelAuthenticationSession.MarshalText encoded, for
// PollBackchannelAuthentication or BackchannelNotification.Authenticates
// on an instance other than the one that began it. A value that isn't
// such an encoding returns an ErrorInvalidRequest *Error.
func ParseBackchannelAuthenticationSession(text string) (BackchannelAuthenticationSession, error) {
	invalid := func(cause error) (BackchannelAuthenticationSession, error) {
		return BackchannelAuthenticationSession{}, newError(ErrorInvalidRequest, "not an encoded backchannel authentication session", cause)
	}
	if len(text) > maxEncodedBackchannelSession {
		return invalid(errors.New("too long"))
	}
	payload, ok := strings.CutPrefix(text, backchannelSessionVersion)
	if !ok {
		return invalid(errors.New("unknown version"))
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return invalid(err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var e encodedBackchannelSession
	if err := dec.Decode(&e); err != nil {
		return invalid(err)
	}
	if e.AuthReqID == "" || e.IntervalMillis <= 0 || e.ExpiresAt.IsZero() {
		return invalid(errors.New("missing auth_req_id, interval or expiry"))
	}
	return BackchannelAuthenticationSession{
		authReqID: e.AuthReqID, interval: time.Duration(e.IntervalMillis) * time.Millisecond,
		expiresAt: e.ExpiresAt, notificationToken: e.NotificationToken,
		openID: e.OpenID,
	}, nil
}

package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"strings"
	"testing"
)

// FuzzParseBackchannelNotification checks ParseBackchannelNotification
// on a CIBA ping callback (§10.2) whose method, Content-Type,
// Authorization header and body an attacker who can reach the
// notification endpoint chooses. Beyond never panicking:
//
//   - a refusal is always an ErrorInvalidRequest *Error;
//   - an accepted one is a POST of application/json, with a body of at
//     most a few kilobytes that is a JSON object whose auth_req_id
//     member, read independently, is the non-empty string AuthReqID
//     returns;
//   - with exactly one Authorization header carrying a non-empty bearer
//     token, it authenticates for the session with that auth_req_id and
//     that token, and not for one with another token or under poll
//     delivery; without one, it authenticates for no session (CIBA
//     §10.2's 401 case, not a parse error).
func FuzzParseBackchannelNotification(f *testing.F) {
	f.Add(uint8(0), "application/json", "Bearer notify-token", false, []byte(`{"auth_req_id":"req-1"}`))
	f.Add(uint8(0), "Application/JSON; charset=utf-8", "bearer t", false, []byte(`{"auth_req_id":"a","auth_req_id":"b","x":[1,{}]}`))
	f.Add(uint8(0), "application/json", "Bearer  spaced", true, []byte(`{"auth_req_id":"req-1"}`))
	f.Add(uint8(1), "application/json", "Bearer t", false, []byte(`{"auth_req_id":"req-1"}`))
	f.Add(uint8(0), "application/json;", "Basic dDp0", false, []byte(`{"AUTH_REQ_ID":"req-1"}`))
	f.Add(uint8(0), "application/json", "Bearer t", false, []byte(`{"auth_req_id":"\ud800"} trailing`))
	f.Fuzz(func(t *testing.T, method uint8, contentType, authorization string, twice bool, body []byte) {
		r := &http.Request{Method: []string{http.MethodPost, http.MethodGet, http.MethodPut, "post"}[method%4], Header: http.Header{}}
		r.Header.Set("Content-Type", contentType)
		r.Header.Add("Authorization", authorization)
		if twice {
			r.Header.Add("Authorization", authorization)
		}
		r.Body = http.NoBody
		if body != nil {
			r.Body = readCloser{bytes.NewReader(body)}
		}
		n, err := ParseBackchannelNotification(r)
		if err != nil {
			var ce *Error
			if !errors.As(err, &ce) || ce.Code() != ErrorInvalidRequest {
				t.Fatalf("ParseBackchannelNotification refused with %v, want an ErrorInvalidRequest *Error", err)
			}
			return
		}
		checkAcceptedNotificationRequest(t, r, len(body))
		checkAcceptedNotification(t, n, authorization, twice, body)
	})
}

type readCloser struct{ *bytes.Reader }

func (readCloser) Close() error { return nil }

// checkAcceptedNotificationRequest checks the shape of a request
// ParseBackchannelNotification accepted.
func checkAcceptedNotificationRequest(t *testing.T, r *http.Request, bodyLen int) {
	t.Helper()
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	switch {
	case r.Method != http.MethodPost:
		t.Fatalf("accepted a %q request", r.Method)
	case err != nil || !strings.EqualFold(mediaType, "application/json"):
		t.Fatalf("accepted Content-Type %q", r.Header.Get("Content-Type"))
	case bodyLen > maxBackchannelNotificationBytes:
		t.Fatalf("accepted a %d-byte body", bodyLen)
	}
}

// checkAcceptedNotification checks an accepted notification carries
// body's auth_req_id, and authenticates with authorization's bearer
// token only when that was the request's one Authorization header.
func checkAcceptedNotification(t *testing.T, n BackchannelNotification, authorization string, twice bool, body []byte) {
	t.Helper()
	want, ok := lastAuthReqID(body)
	if !ok || want == "" || n.AuthReqID() != want {
		t.Fatalf("AuthReqID() = %q, but body %q names %q (%v)", n.AuthReqID(), body, want, ok)
	}
	scheme, token, _ := strings.Cut(authorization, " ")
	if twice || !strings.EqualFold(scheme, "Bearer") || token == "" {
		for _, candidate := range []string{token, authorization} {
			if candidate != "" && n.Authenticates(BackchannelAuthenticationSession{authReqID: want, notificationToken: candidate}) {
				t.Fatalf("Authorization %q (twice: %v) authenticates for token %q", authorization, twice, candidate)
			}
		}
		return
	}
	if !n.Authenticates(BackchannelAuthenticationSession{authReqID: want, notificationToken: token}) {
		t.Fatalf("notification doesn't authenticate for its own auth_req_id %q and token %q", want, token)
	}
	if n.Authenticates(BackchannelAuthenticationSession{authReqID: want, notificationToken: token + "x"}) ||
		n.Authenticates(BackchannelAuthenticationSession{authReqID: want}) {
		t.Fatalf("notification authenticates for another token, or for a poll session")
	}
}

// lastAuthReqID reads body as one JSON object, token by token, and
// returns its last auth_req_id member's string value — the member
// encoding/json's map decoding keeps when a name repeats.
func lastAuthReqID(body []byte) (string, bool) {
	dec := json.NewDecoder(bytes.NewReader(body))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return "", false
	}
	var id string
	found := false
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return "", false
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return "", false
		}
		if key == "auth_req_id" {
			found = json.Unmarshal(value, &id) == nil
		}
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return "", false
	}
	if _, err := dec.Token(); err == nil {
		return "", false // trailing data
	}
	return id, found
}

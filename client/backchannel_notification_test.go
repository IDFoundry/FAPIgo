package client

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// pingRequest builds a ping callback the way server.NewBackchannelNotificationRequest
// does: POST, Content-Type application/json, bearer token, auth_req_id body.
func pingRequest(body string, header map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "https://client.example/ciba-notify", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer notify-token")
	for k, v := range header {
		if v == "" {
			r.Header.Del(k)
		} else {
			r.Header.Set(k, v)
		}
	}
	return r
}

func TestParseBackchannelNotification(t *testing.T) {
	n, err := ParseBackchannelNotification(pingRequest(`{"auth_req_id":"req-1","future_member":true}`, map[string]string{"Content-Type": "application/json; charset=utf-8"}))
	if err != nil {
		t.Fatalf("ParseBackchannelNotification: %v", err)
	}
	if n.AuthReqID() != "req-1" {
		t.Errorf("AuthReqID() = %q, want req-1", n.AuthReqID())
	}
	session := BackchannelAuthenticationSession{authReqID: "req-1", notificationToken: "notify-token"}
	if !n.Authenticates(session) {
		t.Error("Authenticates(its own session) = false, want true")
	}
	for name, other := range map[string]BackchannelAuthenticationSession{
		"another auth_req_id": {authReqID: "req-2", notificationToken: "notify-token"},
		"another token":       {authReqID: "req-1", notificationToken: "other-token"},
		"a poll session":      {authReqID: "req-1"},
	} {
		if n.Authenticates(other) {
			t.Errorf("Authenticates(%s) = true, want false", name)
		}
	}
}

func TestParseBackchannelNotificationBearerSchemeIsCaseInsensitive(t *testing.T) {
	n, err := ParseBackchannelNotification(pingRequest(`{"auth_req_id":"req-1"}`, map[string]string{"Authorization": "bearer notify-token"}))
	if err != nil || !n.Authenticates(BackchannelAuthenticationSession{authReqID: "req-1", notificationToken: "notify-token"}) {
		t.Errorf("lower-case bearer scheme: %v", err)
	}
}

func TestParseBackchannelNotificationRejectsMalformed(t *testing.T) {
	for name, r := range map[string]*http.Request{
		"GET":                 httptest.NewRequest(http.MethodGet, "https://client.example/ciba-notify", nil),
		"form body":           pingRequest(`auth_req_id=req-1`, map[string]string{"Content-Type": "application/x-www-form-urlencoded"}),
		"no content type":     pingRequest(`{"auth_req_id":"req-1"}`, map[string]string{"Content-Type": ""}),
		"no token":            pingRequest(`{"auth_req_id":"req-1"}`, map[string]string{"Authorization": ""}),
		"empty token":         pingRequest(`{"auth_req_id":"req-1"}`, map[string]string{"Authorization": "Bearer "}),
		"basic auth":          pingRequest(`{"auth_req_id":"req-1"}`, map[string]string{"Authorization": "Basic bm90aWZ5"}),
		"not JSON":            pingRequest(`req-1`, nil),
		"array":               pingRequest(`["req-1"]`, nil),
		"no auth_req_id":      pingRequest(`{}`, nil),
		"empty auth_req_id":   pingRequest(`{"auth_req_id":""}`, nil),
		"numeric auth_req_id": pingRequest(`{"auth_req_id":7}`, nil),
		"case variant":        pingRequest(`{"AUTH_REQ_ID":"req-1"}`, nil),
		"too large":           pingRequest(`{"auth_req_id":"req-1","pad":"`+strings.Repeat("x", maxBackchannelNotificationBytes)+`"}`, nil),
	} {
		_, err := ParseBackchannelNotification(r)
		var ce *Error
		if !errors.As(err, &ce) || ce.Code() != ErrorInvalidRequest {
			t.Errorf("ParseBackchannelNotification(%s) = %v, want ErrorInvalidRequest", name, err)
		}
	}
}

func TestParseBackchannelNotificationRejectsTwoAuthorizationHeaders(t *testing.T) {
	r := pingRequest(`{"auth_req_id":"req-1"}`, nil)
	r.Header.Add("Authorization", "Bearer other-token")
	if _, err := ParseBackchannelNotification(r); err == nil {
		t.Error("two Authorization headers = nil error, want error")
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("connection reset") }

func TestParseBackchannelNotificationBodyReadError(t *testing.T) {
	r := pingRequest("", nil)
	r.Body = io.NopCloser(failingReader{})
	if _, err := ParseBackchannelNotification(r); err == nil {
		t.Error("unreadable body = nil error, want error")
	}
}

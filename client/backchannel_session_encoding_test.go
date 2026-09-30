package client

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestBackchannelSessionRoundTrip(t *testing.T) {
	expires := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	for name, s := range map[string]BackchannelAuthenticationSession{
		"ping": {authReqID: "req-1", interval: 5 * time.Second, expiresAt: expires, notificationToken: "notify-token"},
		"poll": {authReqID: "req-2", interval: 2 * time.Second, expiresAt: expires},
	} {
		t.Run(name, func(t *testing.T) {
			text, err := s.MarshalText()
			if err != nil {
				t.Fatalf("MarshalText: %v", err)
			}
			if strings.Contains(string(text), s.authReqID) || (s.notificationToken != "" && strings.Contains(string(text), s.notificationToken)) {
				t.Errorf("encoding %q isn't opaque", text)
			}
			got, err := ParseBackchannelAuthenticationSession(string(text))
			if err != nil {
				t.Fatalf("ParseBackchannelAuthenticationSession: %v", err)
			}
			if got.authReqID != s.authReqID || got.interval != s.interval || !got.expiresAt.Equal(s.expiresAt) || got.notificationToken != s.notificationToken {
				t.Errorf("restored %+v, want %+v", got, s)
			}
		})
	}
}

// TestRestoredSessionAuthenticatesPing covers the reason to restore a
// session: another instance authenticating the ping for it.
func TestRestoredSessionAuthenticatesPing(t *testing.T) {
	begun := BackchannelAuthenticationSession{authReqID: "req-1", interval: time.Second, expiresAt: time.Now().Add(time.Minute), notificationToken: "notify-token"}
	stored, err := begun.MarshalText()
	if err != nil {
		t.Fatal(err)
	}

	var restored BackchannelAuthenticationSession
	if err := restored.UnmarshalText(stored); err != nil {
		t.Fatalf("UnmarshalText: %v", err)
	}
	n, err := ParseBackchannelNotification(pingRequest(`{"auth_req_id":"req-1"}`, nil))
	if err != nil {
		t.Fatal(err)
	}
	if !n.Authenticates(restored) {
		t.Error("the restored session doesn't authenticate its own ping")
	}
}

// TestBackchannelSessionInJSON covers storing a session as a field of
// the app's own record.
func TestBackchannelSessionInJSON(t *testing.T) {
	type pendingPayment struct {
		Order   string                           `json:"order"`
		Session BackchannelAuthenticationSession `json:"session"`
	}
	in := pendingPayment{Order: "o-1", Session: BackchannelAuthenticationSession{authReqID: "req-1", interval: time.Second, expiresAt: time.Now().Round(0), notificationToken: "t"}}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var out pendingPayment
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if out.Session.AuthReqID() != "req-1" || out.Session.NotificationToken() != "t" {
		t.Errorf("restored session %+v", out.Session)
	}
}

func TestParseBackchannelSessionRejects(t *testing.T) {
	encode := func(v any) string {
		raw, _ := json.Marshal(v)
		return "v1." + base64.RawURLEncoding.EncodeToString(raw)
	}
	for name, text := range map[string]string{
		"empty":          "",
		"no version":     base64.RawURLEncoding.EncodeToString([]byte(`{"a":"x","i":1000,"e":"2026-10-01T00:00:00Z"}`)),
		"future version": "v2." + base64.RawURLEncoding.EncodeToString([]byte(`{"a":"x","i":1000,"e":"2026-10-01T00:00:00Z"}`)),
		"not base64":     "v1.!!!",
		"not JSON":       "v1." + base64.RawURLEncoding.EncodeToString([]byte("x")),
		"unknown member": encode(map[string]any{"a": "x", "i": 1000, "e": "2026-10-01T00:00:00Z", "z": 1}),
		"no auth_req_id": encode(map[string]any{"i": 1000, "e": "2026-10-01T00:00:00Z"}),
		"no interval":    encode(map[string]any{"a": "x", "e": "2026-10-01T00:00:00Z"}),
		"no expiry":      encode(map[string]any{"a": "x", "i": 1000}),
		"too long":       "v1." + strings.Repeat("A", maxEncodedBackchannelSession),
	} {
		_, err := ParseBackchannelAuthenticationSession(text)
		var ce *Error
		if !errors.As(err, &ce) || ce.Code() != ErrorInvalidRequest {
			t.Errorf("Parse(%s) = %v, want ErrorInvalidRequest", name, err)
		}
	}
	var s BackchannelAuthenticationSession
	if err := s.UnmarshalText([]byte("v1.!!!")); err == nil {
		t.Error("UnmarshalText(malformed) = nil, want error")
	}
}

func TestMarshalEmptyBackchannelSession(t *testing.T) {
	if _, err := (BackchannelAuthenticationSession{}).MarshalText(); err == nil {
		t.Error("MarshalText(zero session) = nil error, want error")
	}
}

// TestMarshalBackchannelSessionFarFuture covers an expiry past year 9999,
// which time.Time can't encode — an authorization server's expires_in
// could produce one.
func TestMarshalBackchannelSessionFarFuture(t *testing.T) {
	s := BackchannelAuthenticationSession{authReqID: "req-1", interval: time.Second, expiresAt: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)}
	if _, err := s.MarshalText(); err == nil {
		t.Error("MarshalText(year 10000) = nil error, want error")
	}
}

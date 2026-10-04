package sessioncookie_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/client/sessioncookie"
	"github.com/idfoundry/fapigo/fapitest"
	"github.com/idfoundry/fapigo/server"
)

func newKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func newCookie(t *testing.T, keys ...[]byte) *sessioncookie.Cookie {
	t.Helper()
	c, err := sessioncookie.New(keys, sessioncookie.Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// begin starts an authorization against a real server and client.
func begin(t *testing.T) (*fapitest.Harness, client.AuthorizationSession) {
	t.Helper()
	h := fapitest.New(t, fapitest.Config{Profile: server.ProfileFAPISecurity})
	session, err := h.Client.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{Scope: []string{"openid", "accounts"}})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	return h, session
}

func set(t *testing.T, c *sessioncookie.Cookie, session client.AuthorizationSession, value string, now time.Time) *http.Cookie {
	t.Helper()
	w := httptest.NewRecorder()
	if err := c.Set(w, session, value, now); err != nil {
		t.Fatalf("Set: %v", err)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Set set %d cookies, want 1", len(cookies))
	}
	return cookies[0]
}

func callbackWith(ck *http.Cookie) *http.Request {
	r := httptest.NewRequest("GET", "/callback", nil)
	r.AddCookie(&http.Cookie{Name: ck.Name, Value: ck.Value})
	return r
}

// TestCookieCompletesTheAuthorization covers the whole binding: the
// handle read back from the cookie completes the authorization the
// browser began, and the application's value comes back with it.
func TestCookieCompletesTheAuthorization(t *testing.T) {
	h, session := begin(t)
	now := time.Now()
	c := newCookie(t, newKey(t))
	ck := set(t, c, session, "order-42", now)

	if ck.Name != sessioncookie.DefaultName || ck.Path != "/" || !ck.HttpOnly || !ck.Secure || ck.SameSite != http.SameSiteLaxMode {
		t.Errorf("cookie = %+v, want __Host- name, Path /, HttpOnly, Secure, SameSite=Lax", ck)
	}
	if left := int(session.ExpiresAt().Sub(now) / time.Second); ck.MaxAge != left {
		t.Errorf("Max-Age = %d, want %d: the session's remaining life", ck.MaxAge, left)
	}
	if strings.Contains(ck.Value, "order-42") || strings.Contains(ck.Value, session.Handle().String()) {
		t.Error("the cookie shows its contents in the clear")
	}

	handle, value, err := c.Read(callbackWith(ck), now)
	if err != nil || value != "order-42" || handle != session.Handle() {
		t.Fatalf("Read = %q, %q, %v; want the session's handle and order-42", handle.String(), value, err)
	}
	rawQuery, err := h.CaptureCallback(context.Background(), session)
	if err != nil {
		t.Fatalf("CaptureCallback: %v", err)
	}
	if _, err := h.RunAuthorizationCodeFlowWithCallback(context.Background(), handle, rawQuery); err != nil {
		t.Errorf("the handle from the cookie didn't complete the authorization: %v", err)
	}
}

func TestSessionExpiresAt(t *testing.T) {
	before := time.Now()
	_, session := begin(t)
	if got := session.ExpiresAt(); got.Before(before.Add(4*time.Minute)) || got.After(time.Now().Add(6*time.Minute)) {
		t.Errorf("ExpiresAt = %v, want about Limits.SessionLifetime (5m) from now", got)
	}
}

func TestReadRefuses(t *testing.T) {
	_, session := begin(t)
	now := time.Now()
	key := newKey(t)
	c := newCookie(t, key)
	ck := set(t, c, session, "order-42", now)
	tampered := *ck
	// Change a character in the middle of the value, where every bit is
	// significant: replacing the last characters can leave the decoded
	// bytes unchanged, because unpadded base64's final character carries
	// unused bits (and they may already be the replacement).
	mid := len(ck.Value) / 2
	replacement := byte('A')
	if ck.Value[mid] == replacement {
		replacement = 'B'
	}
	tampered.Value = ck.Value[:mid] + string(replacement) + ck.Value[mid+1:]
	otherName, err := sessioncookie.New([][]byte{key}, sessioncookie.Options{Name: "__Host-other"})
	if err != nil {
		t.Fatal(err)
	}

	for name, tc := range map[string]struct {
		c   *sessioncookie.Cookie
		r   *http.Request
		now time.Time
	}{
		"no cookie":                 {c, httptest.NewRequest("GET", "/callback", nil), now},
		"expired":                   {c, callbackWith(ck), session.ExpiresAt()},
		"tampered":                  {c, callbackWith(&tampered), now},
		"another key":               {newCookie(t, newKey(t)), callbackWith(ck), now},
		"sealed for another cookie": {otherName, callbackWith(&http.Cookie{Name: "__Host-other", Value: ck.Value}), now},
		"not base64":                {c, callbackWith(&http.Cookie{Name: ck.Name, Value: "!!"}), now},
	} {
		if _, _, err := tc.c.Read(tc.r, tc.now); !errors.Is(err, sessioncookie.ErrNoSession) {
			t.Errorf("%s: Read = %v, want ErrNoSession", name, err)
		}
	}
}

// TestKeyRotation covers the first key sealing and every key opening.
func TestKeyRotation(t *testing.T) {
	_, session := begin(t)
	now := time.Now()
	oldKey, newKeyBytes := newKey(t), newKey(t)
	ck := set(t, newCookie(t, oldKey), session, "", now)
	if _, _, err := newCookie(t, newKeyBytes, oldKey).Read(callbackWith(ck), now); err != nil {
		t.Errorf("a cookie sealed with the old key doesn't open after rotation: %v", err)
	}
	if _, _, err := newCookie(t, newKeyBytes).Read(callbackWith(ck), now); err == nil {
		t.Error("a cookie sealed with a dropped key still opens")
	}
}

func TestSetRefuses(t *testing.T) {
	_, session := begin(t)
	c := newCookie(t, newKey(t))
	if err := c.Set(httptest.NewRecorder(), session, strings.Repeat("v", 4000), time.Now()); !errors.Is(err, sessioncookie.ErrTooLarge) {
		t.Errorf("Set(a large value) = %v, want ErrTooLarge", err)
	}
	if err := c.Set(httptest.NewRecorder(), session, "", session.ExpiresAt()); err == nil {
		t.Error("Set(an expired session) = nil error")
	}
	if err := c.Set(httptest.NewRecorder(), client.AuthorizationSession{}, "", time.Now()); err == nil {
		t.Error("Set(a session BeginAuthorization didn't return) = nil error")
	}
}

func TestClear(t *testing.T) {
	w := httptest.NewRecorder()
	newCookie(t, newKey(t)).Clear(w)
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].MaxAge >= 0 || cookies[0].Name != sessioncookie.DefaultName {
		t.Errorf("Clear set %+v, want the cookie expired", cookies)
	}
}

func TestNewRefuses(t *testing.T) {
	for name, tc := range map[string]struct {
		keys [][]byte
		opts sessioncookie.Options
	}{
		"no keys":             {nil, sessioncookie.Options{}},
		"short key":           {[][]byte{bytes.Repeat([]byte{1}, 16)}, sessioncookie.Options{}},
		"__Host- with a path": {[][]byte{newKey(t)}, sessioncookie.Options{Path: "/callback"}},
	} {
		if _, err := sessioncookie.New(tc.keys, tc.opts); err == nil {
			t.Errorf("%s: New = nil error, want refusal", name)
		}
	}
}

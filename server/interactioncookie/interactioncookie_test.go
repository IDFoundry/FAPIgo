package interactioncookie_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/server/interactioncookie"
)

func newKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func newCookie(t *testing.T, keys [][]byte, opts interactioncookie.Options) *interactioncookie.Cookie {
	t.Helper()
	if opts.Lifetime == 0 {
		opts.Lifetime = 10 * time.Minute
	}
	c, err := interactioncookie.New(keys, opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func interaction(t *testing.T) (server.InteractionHandle, server.InteractionRequest) {
	t.Helper()
	h, err := server.ParseInteractionHandle("handle-1")
	if err != nil {
		t.Fatal(err)
	}
	return h, server.InteractionRequest{ClientID: "shop", Scope: []string{"openid", "payments"}, Hints: server.AuthenticationHints{LoginHint: "sam@example.com"}}
}

// set seals the interaction with c and returns the cookie it set.
func set(t *testing.T, c *interactioncookie.Cookie, now time.Time) *http.Cookie {
	t.Helper()
	h, in := interaction(t)
	w := httptest.NewRecorder()
	if err := c.Set(w, h, in, now); err != nil {
		t.Fatalf("Set: %v", err)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Set set %d cookies, want 1", len(cookies))
	}
	return cookies[0]
}

func requestWith(ck *http.Cookie) *http.Request {
	r := httptest.NewRequest("POST", "/authorize", nil)
	r.AddCookie(&http.Cookie{Name: ck.Name, Value: ck.Value})
	return r
}

func TestRoundTrip(t *testing.T) {
	now := time.Now()
	c := newCookie(t, [][]byte{newKey(t)}, interactioncookie.Options{})
	ck := set(t, c, now)

	if ck.Name != interactioncookie.DefaultName || ck.Path != "/" || !ck.HttpOnly || !ck.Secure || ck.SameSite != http.SameSiteLaxMode || ck.MaxAge != 600 {
		t.Errorf("cookie = %+v, want __Host- name, Path /, HttpOnly, Secure, SameSite=Lax, Max-Age 600", ck)
	}
	// Encrypted, not just signed: nothing of the interaction shows.
	if strings.Contains(ck.Value, "shop") || strings.Contains(ck.Value, "sam") {
		t.Error("the cookie value shows the interaction in the clear")
	}

	h, in, err := c.Read(requestWith(ck), now.Add(time.Minute))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if h.String() != "handle-1" || in.ClientID != "shop" || in.Hints.LoginHint != "sam@example.com" || len(in.Scope) != 2 {
		t.Errorf("Read = %q, %+v", h.String(), in)
	}
}

func TestReadRefuses(t *testing.T) {
	now := time.Now()
	key := newKey(t)
	c := newCookie(t, [][]byte{key}, interactioncookie.Options{})
	ck := set(t, c, now)
	tampered := *ck
	tampered.Value = ck.Value[:len(ck.Value)-2] + "AA"
	otherName := newCookie(t, [][]byte{key}, interactioncookie.Options{Name: "__Host-other"})

	for name, tc := range map[string]struct {
		c   *interactioncookie.Cookie
		r   *http.Request
		now time.Time
	}{
		"no cookie":                 {c, httptest.NewRequest("POST", "/authorize", nil), now},
		"expired":                   {c, requestWith(ck), now.Add(10 * time.Minute)},
		"tampered":                  {c, requestWith(&tampered), now},
		"another key":               {newCookie(t, [][]byte{newKey(t)}, interactioncookie.Options{}), requestWith(ck), now},
		"sealed for another cookie": {otherName, requestWith(&http.Cookie{Name: "__Host-other", Value: ck.Value}), now},
		"not base64":                {c, requestWith(&http.Cookie{Name: ck.Name, Value: "!!"}), now},
		"too short":                 {c, requestWith(&http.Cookie{Name: ck.Name, Value: "AQ"}), now},
	} {
		if _, _, err := tc.c.Read(tc.r, tc.now); !errors.Is(err, interactioncookie.ErrNoInteraction) {
			t.Errorf("%s: Read = %v, want ErrNoInteraction", name, err)
		}
	}
}

// TestKeyRotation covers the first key sealing and every key opening.
func TestKeyRotation(t *testing.T) {
	now := time.Now()
	oldKey, newKeyBytes := newKey(t), newKey(t)
	ck := set(t, newCookie(t, [][]byte{oldKey}, interactioncookie.Options{}), now)

	rotated := newCookie(t, [][]byte{newKeyBytes, oldKey}, interactioncookie.Options{})
	if _, _, err := rotated.Read(requestWith(ck), now); err != nil {
		t.Errorf("a cookie sealed with the old key doesn't open after rotation: %v", err)
	}
	fresh := set(t, rotated, now)
	if _, _, err := newCookie(t, [][]byte{newKeyBytes}, interactioncookie.Options{}).Read(requestWith(fresh), now); err != nil {
		t.Errorf("a cookie sealed after rotation doesn't open with the new key alone: %v", err)
	}
	if _, _, err := newCookie(t, [][]byte{newKeyBytes}, interactioncookie.Options{}).Read(requestWith(ck), now); err == nil {
		t.Error("a cookie sealed with a dropped key still opens")
	}
}

func TestSetRefusesTooLarge(t *testing.T) {
	c := newCookie(t, [][]byte{newKey(t)}, interactioncookie.Options{})
	h, in := interaction(t)
	in.Scope = []string{strings.Repeat("s", interactioncookie.MaxValueBytes)}
	w := httptest.NewRecorder()
	if err := c.Set(w, h, in, time.Now()); !errors.Is(err, interactioncookie.ErrTooLarge) {
		t.Fatalf("Set(large) = %v, want ErrTooLarge", err)
	}
	if len(w.Result().Cookies()) != 0 {
		t.Error("Set set a cookie it refused")
	}
}

func TestClear(t *testing.T) {
	c := newCookie(t, [][]byte{newKey(t)}, interactioncookie.Options{})
	w := httptest.NewRecorder()
	c.Clear(w)
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].MaxAge >= 0 || cookies[0].Name != interactioncookie.DefaultName {
		t.Errorf("Clear set %+v, want the cookie expired", cookies)
	}
}

func TestNewRefuses(t *testing.T) {
	key := newKey(t)
	for name, tc := range map[string]struct {
		keys [][]byte
		opts interactioncookie.Options
	}{
		"no keys":             {nil, interactioncookie.Options{Lifetime: time.Minute}},
		"short key":           {[][]byte{bytes.Repeat([]byte{1}, 16)}, interactioncookie.Options{Lifetime: time.Minute}},
		"no lifetime":         {[][]byte{key}, interactioncookie.Options{}},
		"__Host- with a path": {[][]byte{key}, interactioncookie.Options{Lifetime: time.Minute, Path: "/authorize"}},
	} {
		if _, err := interactioncookie.New(tc.keys, tc.opts); err == nil {
			t.Errorf("%s: New = nil error, want refusal", name)
		}
	}
	if _, err := interactioncookie.New([][]byte{key}, interactioncookie.Options{Lifetime: time.Minute, Name: "app_interaction", Path: "/authorize"}); err != nil {
		t.Errorf("a non-__Host- name with a path: %v", err)
	}
}

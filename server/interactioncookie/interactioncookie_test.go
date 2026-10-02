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

// required is BeginAuthorization's InteractionRequired for h and in,
// expiring ten minutes after now.
func required(h server.InteractionHandle, in server.InteractionRequest, now time.Time) server.InteractionRequired {
	return server.InteractionRequired{Handle: h, Interaction: in, ExpiresAt: now.Add(10 * time.Minute)}
}

// set seals the interaction with c and returns the cookie it set and
// the form's tag.
func set(t *testing.T, c *interactioncookie.Cookie, now time.Time) (*http.Cookie, string) {
	t.Helper()
	h, in := interaction(t)
	w := httptest.NewRecorder()
	tag, err := c.Set(w, required(h, in, now), now)
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Set set %d cookies, want 1", len(cookies))
	}
	return cookies[0], tag
}

func requestWith(ck *http.Cookie) *http.Request {
	r := httptest.NewRequest("POST", "/authorize", nil)
	r.AddCookie(&http.Cookie{Name: ck.Name, Value: ck.Value})
	return r
}

func TestRoundTrip(t *testing.T) {
	now := time.Now()
	c := newCookie(t, [][]byte{newKey(t)}, interactioncookie.Options{})
	ck, tag := set(t, c, now)

	if ck.Name != interactioncookie.DefaultName || ck.Path != "/" || !ck.HttpOnly || !ck.Secure || ck.SameSite != http.SameSiteLaxMode || ck.MaxAge != 600 {
		t.Errorf("cookie = %+v, want __Host- name, Path /, HttpOnly, Secure, SameSite=Lax, Max-Age 600", ck)
	}
	// Encrypted, not just signed: nothing of the interaction shows.
	if strings.Contains(ck.Value, "shop") || strings.Contains(ck.Value, "sam") {
		t.Error("the cookie value shows the interaction in the clear")
	}

	h, in, err := c.Read(requestWith(ck), now.Add(time.Minute), tag)
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
	ck, tag := set(t, c, now)
	tampered := *ck
	tampered.Value = ck.Value[:len(ck.Value)-2] + "AA"
	otherName := newCookie(t, [][]byte{key}, interactioncookie.Options{Name: "__Host-other"})

	for name, tc := range map[string]struct {
		c   *interactioncookie.Cookie
		r   *http.Request
		now time.Time
		tag string
	}{
		"no cookie":                 {c, httptest.NewRequest("POST", "/authorize", nil), now, tag},
		"expired":                   {c, requestWith(ck), now.Add(10 * time.Minute), tag},
		"tampered":                  {c, requestWith(&tampered), now, tag},
		"another key":               {newCookie(t, [][]byte{newKey(t)}, interactioncookie.Options{}), requestWith(ck), now, tag},
		"sealed for another cookie": {otherName, requestWith(&http.Cookie{Name: "__Host-other", Value: ck.Value}), now, tag},
		"not base64":                {c, requestWith(&http.Cookie{Name: ck.Name, Value: "!!"}), now, tag},
		"too short":                 {c, requestWith(&http.Cookie{Name: ck.Name, Value: "AQ"}), now, tag},
		"no tag":                    {c, requestWith(ck), now, ""},
		"another tag":               {c, requestWith(ck), now, tag + "x"},
	} {
		if _, _, err := tc.c.Read(tc.r, tc.now, tc.tag); !errors.Is(err, interactioncookie.ErrNoInteraction) {
			t.Errorf("%s: Read = %v, want ErrNoInteraction", name, err)
		}
	}
}

// TestKeyRotation covers the first key sealing and every key opening.
func TestKeyRotation(t *testing.T) {
	now := time.Now()
	oldKey, newKeyBytes := newKey(t), newKey(t)
	ck, tag := set(t, newCookie(t, [][]byte{oldKey}, interactioncookie.Options{}), now)

	rotated := newCookie(t, [][]byte{newKeyBytes, oldKey}, interactioncookie.Options{})
	if _, _, err := rotated.Read(requestWith(ck), now, tag); err != nil {
		t.Errorf("a cookie sealed with the old key doesn't open after rotation: %v", err)
	}
	fresh, freshTag := set(t, rotated, now)
	if _, _, err := newCookie(t, [][]byte{newKeyBytes}, interactioncookie.Options{}).Read(requestWith(fresh), now, freshTag); err != nil {
		t.Errorf("a cookie sealed after rotation doesn't open with the new key alone: %v", err)
	}
	if _, _, err := newCookie(t, [][]byte{newKeyBytes}, interactioncookie.Options{}).Read(requestWith(ck), now, tag); err == nil {
		t.Error("a cookie sealed with a dropped key still opens")
	}
}

func TestSetRefusesTooLarge(t *testing.T) {
	c := newCookie(t, [][]byte{newKey(t)}, interactioncookie.Options{})
	h, in := interaction(t)
	in.Scope = []string{strings.Repeat("s", interactioncookie.MaxValueBytes)}
	w := httptest.NewRecorder()
	if _, err := c.Set(w, required(h, in, time.Now()), time.Now()); !errors.Is(err, interactioncookie.ErrTooLarge) {
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
		"no keys":             {nil, interactioncookie.Options{}},
		"short key":           {[][]byte{bytes.Repeat([]byte{1}, 16)}, interactioncookie.Options{}},
		"__Host- with a path": {[][]byte{key}, interactioncookie.Options{Path: "/authorize"}},
	} {
		if _, err := interactioncookie.New(tc.keys, tc.opts); err == nil {
			t.Errorf("%s: New = nil error, want refusal", name)
		}
	}
	if _, err := interactioncookie.New([][]byte{key}, interactioncookie.Options{Name: "app_interaction", Path: "/authorize"}); err != nil {
		t.Errorf("a non-__Host- name with a path: %v", err)
	}
}

// TestSetAndReadRefuseWhatCantRoundTrip covers an interaction that can't
// be encoded, refused by Set, and a sealed handle that isn't one, refused
// by Read.
func TestSetAndReadRefuseWhatCantRoundTrip(t *testing.T) {
	c := newCookie(t, [][]byte{newKey(t)}, interactioncookie.Options{})
	h, _ := interaction(t)
	if _, err := c.Set(httptest.NewRecorder(), required(h, server.InteractionRequest{}, time.Now()), time.Now()); err == nil {
		t.Error("Set(an interaction without a client) = nil error, want refusal")
	}

	_, in := interaction(t)
	w := httptest.NewRecorder()
	tag, err := c.Set(w, required(server.InteractionHandle{}, in, time.Now()), time.Now())
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	if _, _, err := c.Read(requestWith(w.Result().Cookies()[0]), time.Now(), tag); !errors.Is(err, interactioncookie.ErrNoInteraction) {
		t.Errorf("Read(an empty handle) = %v, want ErrNoInteraction", err)
	}
}

// TestReadRefusesAReplacedInteraction covers a second interaction in the
// same browser, replacing the first's cookie: the first page's form no
// longer completes anything, rather than completing the second.
func TestReadRefusesAReplacedInteraction(t *testing.T) {
	now := time.Now()
	c := newCookie(t, [][]byte{newKey(t)}, interactioncookie.Options{})
	_, firstTag := set(t, c, now)

	other, err := server.ParseInteractionHandle("handle-2")
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	secondTag, err := c.Set(w, required(other, server.InteractionRequest{ClientID: "elsewhere"}, now), now)
	if err != nil {
		t.Fatal(err)
	}
	replaced := w.Result().Cookies()[0]

	if _, _, err := c.Read(requestWith(replaced), now, firstTag); !errors.Is(err, interactioncookie.ErrNoInteraction) {
		t.Errorf("Read(the first page's tag) = %v, want ErrNoInteraction", err)
	}
	h, in, err := c.Read(requestWith(replaced), now, secondTag)
	if err != nil || h.String() != "handle-2" || in.ClientID != "elsewhere" {
		t.Errorf("Read(the second page's tag) = %q, %+v, %v", h.String(), in, err)
	}
	if firstTag == secondTag {
		t.Error("two interactions got the same tag")
	}
}

// TestCookieExpiresWithTheInteraction covers the cookie's lifetime: the
// interaction's own (InteractionRequired.ExpiresAt), not one configured
// apart from the server's.
func TestCookieExpiresWithTheInteraction(t *testing.T) {
	now := time.Now()
	c := newCookie(t, [][]byte{newKey(t)}, interactioncookie.Options{})
	h, in := interaction(t)
	a := server.InteractionRequired{Handle: h, Interaction: in, ExpiresAt: now.Add(90 * time.Second)}

	w := httptest.NewRecorder()
	tag, err := c.Set(w, a, now)
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	ck := w.Result().Cookies()[0]
	if ck.MaxAge != 90 {
		t.Errorf("Max-Age = %d, want 90, the interaction's remaining life", ck.MaxAge)
	}
	if _, _, err := c.Read(requestWith(ck), now.Add(89*time.Second), tag); err != nil {
		t.Errorf("Read(before ExpiresAt) = %v", err)
	}
	if _, _, err := c.Read(requestWith(ck), now.Add(90*time.Second), tag); !errors.Is(err, interactioncookie.ErrNoInteraction) {
		t.Errorf("Read(at ExpiresAt) = %v, want ErrNoInteraction", err)
	}

	for name, expiresAt := range map[string]time.Time{"expired": now.Add(-time.Second), "unset": {}, "under a second left": now.Add(500 * time.Millisecond)} {
		a.ExpiresAt = expiresAt
		if _, err := c.Set(httptest.NewRecorder(), a, now); err == nil {
			t.Errorf("Set(%s interaction) = nil error", name)
		}
	}
}

package client

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
)

func sessionSealKey(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

// sessionSealer is a BackchannelSessionSealer for a client of issuer
// with keys.
func sessionSealer(t *testing.T, issuer string, keys ...[]byte) *BackchannelSessionSealer {
	t.Helper()
	iss, err := fapi.ParseIssuerURL(issuer)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewBackchannelSessionSealer(&Client{cfg: Config{Issuer: iss, ClientID: "client-1"}}, keys)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestBackchannelSessionSealRoundTrip(t *testing.T) {
	expires := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	s := sessionSealer(t, "https://as.example.com", sessionSealKey(1))
	for name, session := range map[string]BackchannelAuthenticationSession{
		"ping":   {authReqID: "req-1", interval: 5 * time.Second, expiresAt: expires, notificationToken: "notify-token"},
		"poll":   {authReqID: "req-2", interval: 2 * time.Second, expiresAt: expires},
		"openid": {authReqID: "req-3", interval: time.Second, expiresAt: expires, openID: true},
	} {
		t.Run(name, func(t *testing.T) {
			sealed, err := s.Seal(session, "user-1")
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			if bytes.Contains(sealed, []byte(session.authReqID)) || (session.notificationToken != "" && bytes.Contains(sealed, []byte(session.notificationToken))) {
				t.Errorf("sealed session %q isn't opaque", sealed)
			}
			got, reseal, err := s.Open(sealed, "user-1")
			if err != nil || reseal {
				t.Fatalf("Open = reseal %v, %v", reseal, err)
			}
			if got.authReqID != session.authReqID || got.interval != session.interval || !got.expiresAt.Equal(session.expiresAt) ||
				got.notificationToken != session.notificationToken || got.openID != session.openID {
				t.Errorf("opened %+v, want %+v", got, session)
			}
		})
	}
}

// TestOpenedSessionAuthenticatesPing covers the reason to restore a
// session: another instance authenticating the ping for it.
func TestOpenedSessionAuthenticatesPing(t *testing.T) {
	s := sessionSealer(t, "https://as.example.com", sessionSealKey(1))
	begun := BackchannelAuthenticationSession{authReqID: "req-1", interval: time.Second, expiresAt: time.Now().Add(time.Minute), notificationToken: "notify-token"}
	sealed, err := s.Seal(begun, "user-1")
	if err != nil {
		t.Fatal(err)
	}
	restored, _, err := s.Open(sealed, "user-1")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	n, err := ParseBackchannelNotification(pingRequest(`{"auth_req_id":"req-1"}`, nil))
	if err != nil {
		t.Fatal(err)
	}
	if !n.Authenticates(restored) {
		t.Error("the restored session doesn't authenticate its own ping")
	}
}

// TestBackchannelSessionSealerRotatesKeys: a session sealed with an old
// key opens while that key is listed, and Open asks for it to be sealed
// again; once the key is gone, it doesn't open.
func TestBackchannelSessionSealerRotatesKeys(t *testing.T) {
	session := BackchannelAuthenticationSession{authReqID: "req-1", interval: time.Second, expiresAt: time.Now().Add(time.Minute)}
	sealed, err := sessionSealer(t, "https://as.example.com", sessionSealKey(1)).Seal(session, "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, reseal, err := sessionSealer(t, "https://as.example.com", sessionSealKey(2), sessionSealKey(1)).Open(sealed, "user-1"); err != nil || !reseal {
		t.Errorf("Open(old key, still listed) = reseal %v, %v; want reseal", reseal, err)
	}
	if _, _, err := sessionSealer(t, "https://as.example.com", sessionSealKey(2)).Open(sealed, "user-1"); !errors.Is(err, ErrUnreadableBackchannelSession) {
		t.Errorf("Open(old key, gone) = %v, want ErrUnreadableBackchannelSession", err)
	}
}

func TestBackchannelSessionSealerRefuses(t *testing.T) {
	s := sessionSealer(t, "https://as.example.com", sessionSealKey(1))
	good, err := s.Seal(BackchannelAuthenticationSession{authReqID: "req-1", interval: time.Second, expiresAt: time.Now().Add(time.Minute), openID: true}, "user-1")
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Clone(good)
	tampered[len(tampered)/2] ^= 1
	sealPlain := func(v any) []byte {
		raw, _ := json.Marshal(v)
		return s.keys.seal(backchannelSessionSealVersion, raw, s.additionalData("user-1"))
	}
	other := func(issuer string, key []byte) []byte {
		b, err := sessionSealer(t, issuer, key).Seal(BackchannelAuthenticationSession{authReqID: "req-1", interval: time.Second, expiresAt: time.Now()}, "user-1")
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	// The encoding v0.51 and earlier wrote: unsealed, so never opened.
	oldRaw, _ := json.Marshal(map[string]any{"a": "req-1", "i": 1000, "e": "2026-10-01T00:00:00Z"})
	old := []byte("v1." + base64.RawURLEncoding.EncodeToString(oldRaw))

	for name, sealed := range map[string][]byte{
		"empty":          nil,
		"v0.51 encoding": old,
		"tampered":       tampered,
		"another issuer": other("https://other.example.com", sessionSealKey(1)),
		"unknown key":    other("https://as.example.com", sessionSealKey(9)),
		"too long":       bytes.Repeat([]byte{backchannelSessionSealVersion}, maxSealedBackchannelSession+1),
		"not JSON":       s.keys.seal(backchannelSessionSealVersion, []byte("x"), s.additionalData("user-1")),
		"unknown member": sealPlain(map[string]any{"a": "x", "i": 1000, "e": "2026-10-01T00:00:00Z", "z": 1}),
		"no auth_req_id": sealPlain(map[string]any{"i": 1000, "e": "2026-10-01T00:00:00Z"}),
		"no interval":    sealPlain(map[string]any{"a": "x", "e": "2026-10-01T00:00:00Z"}),
		"no expiry":      sealPlain(map[string]any{"a": "x", "i": 1000}),
	} {
		_, _, err := s.Open(sealed, "user-1")
		var ce *Error
		if !errors.As(err, &ce) || ce.Code() != ErrorInvalidRequest || !errors.Is(err, ErrUnreadableBackchannelSession) {
			t.Errorf("Open(%s) = %v, want ErrorInvalidRequest wrapping ErrUnreadableBackchannelSession", name, err)
		}
	}
}

func TestSealEmptyBackchannelSession(t *testing.T) {
	if _, err := sessionSealer(t, "https://as.example.com", sessionSealKey(1)).Seal(BackchannelAuthenticationSession{}, "user-1"); err == nil {
		t.Error("Seal(zero session) = nil error, want error")
	}
}

// TestSealBackchannelSessionFarFuture covers an expiry past year 9999,
// which time.Time can't encode — an authorization server's expires_in
// could produce one.
func TestSealBackchannelSessionFarFuture(t *testing.T) {
	s := BackchannelAuthenticationSession{authReqID: "req-1", interval: time.Second, expiresAt: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)}
	if _, err := sessionSealer(t, "https://as.example.com", sessionSealKey(1)).Seal(s, "user-1"); err == nil {
		t.Error("Seal(year 10000) = nil error, want error")
	}
}

func TestNewBackchannelSessionSealerRefuses(t *testing.T) {
	for name, keys := range map[string][][]byte{
		"no keys":   nil,
		"short key": {bytes.Repeat([]byte{1}, 16)},
	} {
		if _, err := NewBackchannelSessionSealer(&Client{}, keys); err == nil || !strings.Contains(err.Error(), "backchannel session") {
			t.Errorf("NewBackchannelSessionSealer(%s) = %v, want an error naming the sealer", name, err)
		}
	}
	if _, err := NewBackchannelSessionSealer(nil, [][]byte{sessionSealKey(1)}); err == nil {
		t.Error("NewBackchannelSessionSealer(nil client) = nil error, want error")
	}
}

// TestBackchannelSessionSealerBindsOwner: a session opens only for the
// owner it was sealed for, so one leaked from another user's storage
// doesn't open under this user's; and an owner is required to seal.
func TestBackchannelSessionSealerBindsOwner(t *testing.T) {
	s := sessionSealer(t, "https://as.example.com", sessionSealKey(1))
	session := BackchannelAuthenticationSession{authReqID: "req-1", interval: time.Second, expiresAt: time.Now().Add(time.Minute)}
	sealed, err := s.Seal(session, "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if got, _, err := s.Open(sealed, "user-1"); err != nil || got.authReqID != "req-1" {
		t.Fatalf("Open(same owner) = %+v, %v; want the session", got, err)
	}
	for _, owner := range []string{"user-2", "", "user-1 "} {
		if _, _, err := s.Open(sealed, owner); !errors.Is(err, ErrUnreadableBackchannelSession) {
			t.Errorf("Open(owner %q) = %v, want ErrUnreadableBackchannelSession", owner, err)
		}
	}
	if _, err := s.Seal(session, ""); err == nil {
		t.Error("Seal(no owner) = nil error, want error")
	}
}

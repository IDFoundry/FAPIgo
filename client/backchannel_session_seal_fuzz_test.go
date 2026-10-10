package client

import (
	"testing"
	"time"
)

// FuzzOpenBackchannelSession: Open never panics on arbitrary stored
// bytes, never opens for another owner, and only opens the one session
// sealed here.
func FuzzOpenBackchannelSession(f *testing.F) {
	s := sessionSealer(f, "https://as.example", sessionSealKey(1))
	begun := BackchannelAuthenticationSession{authReqID: "req-1", interval: time.Second, expiresAt: time.Unix(1_900_000_000, 0), notificationToken: "nt"}
	sealed, err := s.Seal(begun, "user-1")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(sealed, "user-1")
	f.Add(sealed, "user-2")
	f.Add([]byte{}, "")
	f.Fuzz(func(t *testing.T, b []byte, owner string) {
		got, _, err := s.Open(b, owner)
		if err != nil {
			return
		}
		if owner != "user-1" {
			t.Fatalf("opened a session for owner %q, sealed for user-1", owner)
		}
		if got.authReqID != begun.authReqID || got.notificationToken != begun.notificationToken {
			t.Fatalf("opened a session nobody sealed: %+v", got)
		}
	})
}

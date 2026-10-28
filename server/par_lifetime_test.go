package server_test

import (
	"testing"
	"time"

	"github.com/idfoundry/fapigo/server"
)

// RFC 9126 §2.2 reports a pushed request's lifetime as expires_in, a
// positive whole number of seconds: a lifetime under a second would be
// sent as 0, so New refuses it.
func TestNewRequiresAPushedRequestLifetimeOfAtLeastASecond(t *testing.T) {
	for lifetime, wantErr := range map[time.Duration]bool{
		999 * time.Millisecond: true,
		time.Nanosecond:        true,
		time.Second:            false,
	} {
		cfg := validConfig(t)
		cfg.Limits.PushedRequestLifetime = lifetime
		if _, err := server.New(cfg, validDependencies()); (err != nil) != wantErr {
			t.Errorf("New(PushedRequestLifetime %v) error = %v, want error %v", lifetime, err, wantErr)
		}
	}
}

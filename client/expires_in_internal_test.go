package client

import (
	"math"
	"testing"
	"time"
)

// TestExpiresInDurationClamps: an expires_in too large for a Duration is
// clamped to the largest one, never wrapped into a negative or small
// lifetime.
func TestExpiresInDurationClamps(t *testing.T) {
	for seconds, want := range map[int64]time.Duration{
		300:                     300 * time.Second,
		maxExpiresInSeconds:     time.Duration(maxExpiresInSeconds) * time.Second,
		maxExpiresInSeconds + 1: time.Duration(maxExpiresInSeconds) * time.Second,
		math.MaxInt64:           time.Duration(maxExpiresInSeconds) * time.Second,
	} {
		if got := expiresInDuration(seconds); got != want || got <= 0 {
			t.Errorf("expiresInDuration(%d) = %v, want %v", seconds, got, want)
		}
	}
}

// TestTokenSetFromResponseClampsExpiresIn: a token response's huge
// expires_in yields a long, positive ExpiresIn.
func TestTokenSetFromResponseClampsExpiresIn(t *testing.T) {
	c := &Client{cfg: Config{}, deps: Dependencies{Clock: SystemClock{}}}
	ts, err := c.tokenSetFromResponse(t.Context(), []byte(`{"access_token":"at","token_type":"DPoP","expires_in":9223372036854775807}`), "")
	if err != nil {
		t.Fatalf("tokenSetFromResponse: %v", err)
	}
	if ts.ExpiresIn <= 0 || !ts.HasExpiresIn {
		t.Errorf("ExpiresIn = %v (%v), want a positive clamped lifetime", ts.ExpiresIn, ts.HasExpiresIn)
	}
}

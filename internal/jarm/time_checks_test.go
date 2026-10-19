package jarm

import (
	"errors"
	"testing"
	"time"
)

// A response's exp may sit up to MaxLifetime plus MaxClockSkew away, so
// one from an authorization server whose clock runs ahead within the
// skew still verifies.
func TestVerifyLifetimeAllowsClockSkew(t *testing.T) {
	key := generateKey(t)
	clientNow := time.Unix(1_800_000_000, 0)
	policy := basePolicy(clientNow)
	policy.MaxClockSkew = 10 * time.Second
	for _, tc := range []struct {
		name     string
		lifetime time.Duration
		want     error
	}{
		{"at MaxLifetime plus the skew", policy.MaxLifetime + policy.MaxClockSkew, nil},
		{"past it", policy.MaxLifetime + policy.MaxClockSkew + time.Second, ErrLifetimeExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := Parse(createTestResponse(t, key, clientNow, tc.lifetime, successParameters(t)))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := resp.Verify(&key.PublicKey, policy); !errors.Is(err, tc.want) {
				t.Errorf("Verify = %v, want %v", err, tc.want)
			}
		})
	}
}

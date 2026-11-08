package jarm

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
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

// A response whose nbf lies more than MaxClockSkew in the future isn't
// valid yet; one within the skew is.
func TestVerifyBoundsFutureNotBefore(t *testing.T) {
	key := generateKey(t)
	now := time.Unix(1_800_000_000, 0)
	policy := basePolicy(now)
	policy.MaxClockSkew = 10 * time.Second
	for _, tc := range []struct {
		name string
		nbf  time.Time
		want error
	}{
		{"nbf now", now, nil},
		{"nbf within the skew", now.Add(10 * time.Second), nil},
		{"nbf past the skew", now.Add(11 * time.Second), ErrNotYetValid},
		{"nbf an hour ahead", now.Add(time.Hour), ErrNotYetValid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload, err := json.Marshal(map[string]any{
				"iss": "https://as.example", "aud": "client-123", "code": "auth-code", "state": "state-1",
				"exp": now.Add(time.Minute).Unix(), "nbf": tc.nbf.Unix(),
			})
			if err != nil {
				t.Fatal(err)
			}
			compact, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256}, payload)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := Parse(compact)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := resp.Verify(&key.PublicKey, policy); !errors.Is(err, tc.want) {
				t.Errorf("Verify = %v, want %v", err, tc.want)
			}
		})
	}
}

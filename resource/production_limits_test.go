package resource_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// TestVerifyBoundsTokenLifetimeWithoutRevocation covers
// NoRevocationUntilExpiry: revocation isn't checked, so Verify refuses a
// token expiring further ahead than its MaxTokenLifetime (plus
// MaxClockSkew, 5 seconds here), whatever resolver resolved it, and
// accepts one within it.
func TestVerifyBoundsTokenLifetimeWithoutRevocation(t *testing.T) {
	for name, tc := range map[string]struct {
		lifetime time.Duration
		accepted bool
	}{
		"well within":                {5 * time.Minute, true},
		"at the bound":               {10 * time.Minute, true},
		"within the skew":            {10*time.Minute + 4*time.Second, true},
		"past the bound and skew":    {10*time.Minute + 6*time.Second, false},
		"an hour, as if unrevocable": {time.Hour, false},
	} {
		t.Run(name, func(t *testing.T) {
			f := newOpaqueFixture(t, tc.lifetime)
			v, err := resource.NewVerifier(validConfig(t), resource.Dependencies{
				AccessTokens: resource.OpaqueAccessTokens{Issuer: testIssuerURL, Store: f.store},
				Replay:       &fakeReplayStore{},
				Revocation:   resource.NoRevocationUntilExpiry{MaxTokenLifetime: 10 * time.Minute},
				Clock:        fixedClock{now: f.now},
			})
			if err != nil {
				t.Fatalf("NewVerifier: %v", err)
			}
			_, err = v.Verify(context.Background(), resource.VerifyRequest{
				Method: "GET", URL: f.target,
				Authorization: "DPoP " + f.rawToken,
				DPoPProofs:    []string{f.proof(t, f.dpopKey)},
			})
			assertLifetimeOutcome(t, err, tc.accepted)
		})
	}
}

// assertLifetimeOutcome checks err is nil when accepted, and otherwise
// an invalid_token refusal.
func assertLifetimeOutcome(t *testing.T, err error, accepted bool) {
	t.Helper()
	if accepted {
		if err != nil {
			t.Fatalf("Verify = %v, want accepted", err)
		}
		return
	}
	var rerr *resource.Error
	if !errors.As(err, &rerr) || rerr.Code() != resource.ErrorInvalidToken {
		t.Fatalf("Verify = %v, want invalid_token", err)
	}
}

// TestNewVerifierRefusesNonPositiveUnrevocableLifetime covers
// NoRevocationUntilExpiry's required MaxTokenLifetime, under either
// assurance level, by value and by pointer.
func TestNewVerifierRefusesNonPositiveUnrevocableLifetime(t *testing.T) {
	for name, revocation := range map[string]resource.RevocationChecker{
		"zero":             resource.NoRevocationUntilExpiry{},
		"negative":         resource.NoRevocationUntilExpiry{MaxTokenLifetime: -time.Minute},
		"pointer, zero":    &resource.NoRevocationUntilExpiry{},
		"production, zero": resource.NoRevocationUntilExpiry{},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, deps := validConfig(t), resource.Dependencies{
				AccessTokens: validAccessTokens(t), Replay: &fakeReplayStore{}, Clock: fixedClock{now: time.Now()},
			}
			if strings.HasPrefix(name, "production") {
				cfg, deps = productionSetup(t)
			}
			deps.Revocation = revocation
			_, err := resource.NewVerifier(cfg, deps)
			if err == nil || !strings.Contains(err.Error(), "MaxTokenLifetime must be positive") {
				t.Fatalf("NewVerifier = %v, want MaxTokenLifetime refused", err)
			}
		})
	}
}

// TestNewVerifierDevelopmentAcceptsNoRevocation: the production refusal
// of NoRevocation leaves development as it was.
func TestNewVerifierDevelopmentAcceptsNoRevocation(t *testing.T) {
	_, err := resource.NewVerifier(validConfig(t), resource.Dependencies{
		AccessTokens: validAccessTokens(t), Replay: &fakeReplayStore{},
		Revocation: resource.NoRevocation{}, Clock: fixedClock{now: time.Now()},
	})
	if err != nil {
		t.Fatalf("NewVerifier(development, NoRevocation) = %v", err)
	}
}

// TestNewVerifierRejectsTypedNilDependencies covers a Dependencies field
// holding a typed nil, which isn't == nil: NewVerifier refuses it
// rather than failing on the first request. Every interface field
// productionSetup sets is tried, as a nil pointer of its own type (or a
// pointer to it, for a value type), under development assurance.
func TestNewVerifierRejectsTypedNilDependencies(t *testing.T) {
	_, base := productionSetup(t)
	base.Nonces = memstore.NewNonceStore()
	v := reflect.ValueOf(base)
	for i := range v.NumField() {
		field := v.Type().Field(i)
		value := v.Field(i)
		if field.Type.Kind() != reflect.Interface || value.IsNil() {
			continue
		}
		t.Run(field.Name, func(t *testing.T) {
			typed := value.Elem().Type()
			if typed.Kind() != reflect.Pointer {
				typed = reflect.PointerTo(typed)
			}
			deps := base
			reflect.ValueOf(&deps).Elem().Field(i).Set(reflect.Zero(typed))
			cfg := validConfig(t)
			cfg.Limits.DPoPNonceLifetime = time.Minute
			_, err := resource.NewVerifier(cfg, deps)
			if err == nil || !strings.Contains(err.Error(), "is a nil") {
				t.Fatalf("NewVerifier = %v, want a typed nil refused", err)
			}
		})
	}
}

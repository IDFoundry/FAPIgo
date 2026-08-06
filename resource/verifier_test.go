package resource_test

import (
	"context"
	"testing"
	"time"

	fapi "github.com/osanderson/go-fapi"
	"github.com/osanderson/go-fapi/keys"
	"github.com/osanderson/go-fapi/resource"
	"github.com/osanderson/go-fapi/storage"
)

const testIssuer = "https://as.example.com"

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

type fakeIssuerKeySource struct {
	set keys.IssuerKeySet
	err error
}

func (f *fakeIssuerKeySource) ResolveIssuerKeys(ctx context.Context, req keys.IssuerKeyRequest) (keys.IssuerKeySet, error) {
	if f.err != nil {
		return keys.IssuerKeySet{}, f.err
	}
	return f.set, nil
}

type fakeReplayStore struct {
	seen map[[32]byte]bool
	err  error
}

func (f *fakeReplayStore) UseOnce(ctx context.Context, use storage.ReplayUse) error {
	if f.err != nil {
		return f.err
	}
	if f.seen == nil {
		f.seen = map[[32]byte]bool{}
	}
	if f.seen[use.Digest] {
		return errAlreadyUsed
	}
	f.seen[use.Digest] = true
	return nil
}

var errAlreadyUsed = &replayError{}

type replayError struct{}

func (*replayError) Error() string { return "replay: already used" }

func validConfig(t *testing.T) resource.Config {
	t.Helper()
	issuer, err := fapi.ParseIssuerURL(testIssuer)
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}
	return resource.Config{
		Issuer:    issuer,
		Audience:  testIssuer,
		Algorithm: fapi.ES256,
		Limits: resource.Limits{
			MaxTokenLifetime: 5 * time.Minute,
			MaxDPoPProofAge:  time.Minute,
			MaxClockSkew:     5 * time.Second,
		},
	}
}

func validDependencies() resource.Dependencies {
	return resource.Dependencies{
		IssuerKeys: &fakeIssuerKeySource{},
		Replay:     &fakeReplayStore{},
		Clock:      fixedClock{now: time.Now()},
	}
}

func TestNewVerifierAcceptsValidConfig(t *testing.T) {
	if _, err := resource.NewVerifier(validConfig(t), validDependencies()); err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
}

func TestNewVerifierRejectsInvalidConfig(t *testing.T) {
	cases := map[string]func(*resource.Config){
		"zero issuer":             func(c *resource.Config) { c.Issuer = fapi.URL{} },
		"empty audience":          func(c *resource.Config) { c.Audience = "" },
		"invalid algorithm":       func(c *resource.Config) { c.Algorithm = 0 },
		"zero max token lifetime": func(c *resource.Config) { c.Limits.MaxTokenLifetime = 0 },
		"zero max dpop proof age": func(c *resource.Config) { c.Limits.MaxDPoPProofAge = 0 },
		"negative clock skew":     func(c *resource.Config) { c.Limits.MaxClockSkew = -time.Second },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := validConfig(t)
			mutate(&cfg)
			if _, err := resource.NewVerifier(cfg, validDependencies()); err == nil {
				t.Fatalf("NewVerifier(%s) = nil error, want error", name)
			}
		})
	}
}

func TestNewVerifierRejectsMissingDependencies(t *testing.T) {
	cases := map[string]func(*resource.Dependencies){
		"nil issuer keys": func(d *resource.Dependencies) { d.IssuerKeys = nil },
		"nil replay":      func(d *resource.Dependencies) { d.Replay = nil },
		"nil clock":       func(d *resource.Dependencies) { d.Clock = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			deps := validDependencies()
			mutate(&deps)
			if _, err := resource.NewVerifier(validConfig(t), deps); err == nil {
				t.Fatalf("NewVerifier(%s) = nil error, want error", name)
			}
		})
	}
}

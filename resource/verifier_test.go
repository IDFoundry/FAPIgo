package resource_test

import (
	"context"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/storage"
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

type fakeRevocationChecker struct {
	revoked map[string]bool
	err     error
}

func (f *fakeRevocationChecker) IsRevoked(_ context.Context, key string) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	return f.revoked[key], nil
}

func validConfig(t *testing.T) resource.Config {
	t.Helper()
	return resource.Config{
		Limits: resource.Limits{
			MaxDPoPProofAge: time.Minute,
			MaxClockSkew:    5 * time.Second,
		},
	}
}

func validAccessTokens(t *testing.T) resource.AccessTokenResolver {
	t.Helper()
	issuer, err := fapi.ParseIssuerURL(testIssuer)
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}
	jwt, err := resource.NewJWTAccessTokens(&fakeIssuerKeySource{}, issuer, testIssuer, fapi.ES256, 5*time.Minute)
	if err != nil {
		t.Fatalf("NewJWTAccessTokens: %v", err)
	}
	return jwt
}

func validDependencies(t *testing.T) resource.Dependencies {
	t.Helper()
	return resource.Dependencies{
		AccessTokens: validAccessTokens(t),
		Replay:       &fakeReplayStore{},
		Revocation:   &fakeRevocationChecker{},
		Clock:        fixedClock{now: time.Now()},
	}
}

func TestNewVerifierAcceptsValidConfig(t *testing.T) {
	if _, err := resource.NewVerifier(validConfig(t), validDependencies(t)); err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
}

func TestNewVerifierRejectsInvalidConfig(t *testing.T) {
	cases := map[string]func(*resource.Config){
		"zero max dpop proof age": func(c *resource.Config) { c.Limits.MaxDPoPProofAge = 0 },
		"negative clock skew":     func(c *resource.Config) { c.Limits.MaxClockSkew = -time.Second },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := validConfig(t)
			mutate(&cfg)
			if _, err := resource.NewVerifier(cfg, validDependencies(t)); err == nil {
				t.Fatalf("NewVerifier(%s) = nil error, want error", name)
			}
		})
	}
}

// TestNewJWTAccessTokensRejectsInvalid covers what
// TestNewVerifierRejectsInvalidConfig used to check directly against
// resource.Config before issuer/audience/algorithm/max-token-lifetime
// and their validation moved into JWTAccessTokens itself (see
// resource/accesstoken.go).
func TestNewJWTAccessTokensRejectsInvalid(t *testing.T) {
	issuer, err := fapi.ParseIssuerURL(testIssuer)
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}
	type params struct {
		issuerKeys       keys.IssuerKeySource
		issuer           fapi.URL
		audience         string
		algorithm        fapi.SignatureAlgorithm
		maxTokenLifetime time.Duration
	}
	valid := func() params {
		return params{&fakeIssuerKeySource{}, issuer, testIssuer, fapi.ES256, 5 * time.Minute}
	}
	cases := map[string]func(*params){
		"nil issuer keys":         func(p *params) { p.issuerKeys = nil },
		"zero issuer":             func(p *params) { p.issuer = fapi.URL{} },
		"empty audience":          func(p *params) { p.audience = "" },
		"invalid algorithm":       func(p *params) { p.algorithm = 0 },
		"zero max token lifetime": func(p *params) { p.maxTokenLifetime = 0 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := valid()
			mutate(&p)
			if _, err := resource.NewJWTAccessTokens(p.issuerKeys, p.issuer, p.audience, p.algorithm, p.maxTokenLifetime); err == nil {
				t.Fatalf("NewJWTAccessTokens(%s) = nil error, want error", name)
			}
		})
	}
}

// TestNewOpaqueAccessTokensRejectsInvalid — every existing test that
// uses OpaqueAccessTokens builds it as a bare struct literal
// (OpaqueAccessTokens{Store: store}), bypassing this validating
// constructor entirely, so its one check (reject a nil store) had
// never actually run.
func TestNewOpaqueAccessTokensRejectsInvalid(t *testing.T) {
	if _, err := resource.NewOpaqueAccessTokens(nil); err == nil {
		t.Fatalf("NewOpaqueAccessTokens(nil store) = nil error, want error")
	}
}

func TestNewVerifierRejectsMissingDependencies(t *testing.T) {
	cases := map[string]func(*resource.Dependencies){
		"nil access tokens": func(d *resource.Dependencies) { d.AccessTokens = nil },
		"nil replay":        func(d *resource.Dependencies) { d.Replay = nil },
		"nil revocation":    func(d *resource.Dependencies) { d.Revocation = nil },
		"nil clock":         func(d *resource.Dependencies) { d.Clock = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			deps := validDependencies(t)
			mutate(&deps)
			if _, err := resource.NewVerifier(validConfig(t), deps); err == nil {
				t.Fatalf("NewVerifier(%s) = nil error, want error", name)
			}
		})
	}
}

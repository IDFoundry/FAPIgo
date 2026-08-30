package resource_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/token"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
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
	jwt, err := resource.NewJWTAccessTokens(&fakeIssuerKeySource{}, issuer, testIssuer, fapi.ES256, 5*time.Minute, 8)
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

// TestNewVerifierAcceptsZeroNonceLifetimeWhenNoncesUnset confirms
// DPoPNonceLifetime is only validated when Dependencies.Nonces is
// actually set — a verifier that never opts into nonce-challenge
// support shouldn't be forced to set an otherwise-unused limit.
func TestNewVerifierAcceptsZeroNonceLifetimeWhenNoncesUnset(t *testing.T) {
	cfg := validConfig(t)
	cfg.Limits.DPoPNonceLifetime = 0
	if _, err := resource.NewVerifier(cfg, validDependencies(t)); err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
}

func TestNewVerifierRejectsInvalidNonceConfig(t *testing.T) {
	nonces := memstore.NewNonceStore()

	t.Run("zero nonce lifetime with nonces set", func(t *testing.T) {
		cfg := validConfig(t)
		cfg.Limits.DPoPNonceLifetime = 0
		deps := validDependencies(t)
		deps.Nonces = nonces
		deps.Random = rand.Reader
		if _, err := resource.NewVerifier(cfg, deps); err == nil {
			t.Fatalf("NewVerifier(zero nonce lifetime, nonces set) = nil error, want error")
		}
	})

	t.Run("nil random with nonces set", func(t *testing.T) {
		cfg := validConfig(t)
		cfg.Limits.DPoPNonceLifetime = time.Minute
		deps := validDependencies(t)
		deps.Nonces = nonces
		if _, err := resource.NewVerifier(cfg, deps); err == nil {
			t.Fatalf("NewVerifier(nil random, nonces set) = nil error, want error")
		}
	})

	t.Run("nonces and random both set", func(t *testing.T) {
		cfg := validConfig(t)
		cfg.Limits.DPoPNonceLifetime = time.Minute
		deps := validDependencies(t)
		deps.Nonces = nonces
		deps.Random = rand.Reader
		if _, err := resource.NewVerifier(cfg, deps); err != nil {
			t.Fatalf("NewVerifier: %v", err)
		}
	})
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
		maxKeyCandidates int
	}
	valid := func() params {
		return params{&fakeIssuerKeySource{}, issuer, testIssuer, fapi.ES256, 5 * time.Minute, 8}
	}
	cases := map[string]func(*params){
		"nil issuer keys":         func(p *params) { p.issuerKeys = nil },
		"zero issuer":             func(p *params) { p.issuer = fapi.URL{} },
		"empty audience":          func(p *params) { p.audience = "" },
		"invalid algorithm":       func(p *params) { p.algorithm = 0 },
		"zero max token lifetime": func(p *params) { p.maxTokenLifetime = 0 },
		"zero max key candidates": func(p *params) { p.maxKeyCandidates = 0 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := valid()
			mutate(&p)
			if _, err := resource.NewJWTAccessTokens(p.issuerKeys, p.issuer, p.audience, p.algorithm, p.maxTokenLifetime, p.maxKeyCandidates); err == nil {
				t.Fatalf("NewJWTAccessTokens(%s) = nil error, want error", name)
			}
		})
	}
}

// jwtAccessTokensWithCandidateKeys builds a JWTAccessTokens whose
// IssuerKeySource always returns count freshly-generated ES256 keys (in
// a fixed order) plus one real signing key, and issues a token signed
// with that real key — for exercising MaxKeyCandidates directly, not
// through the full Verifier/DPoP flow.
func jwtAccessTokensWithCandidateKeys(t *testing.T, decoyCount, maxKeyCandidates int, signingKeyIndex int) (resource.JWTAccessTokens, string) {
	t.Helper()
	issuerURL, err := fapi.ParseIssuerURL(testIssuer)
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}

	var signingKey *ecdsa.PrivateKey
	issuerKeys := make([]keys.IssuerKey, decoyCount+1)
	for i := range issuerKeys {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate key %d: %v", i, err)
		}
		issuerKeys[i] = keys.IssuerKey{KeyID: fmt.Sprintf("kid-%d", i), Algorithm: fapi.ES256, PublicKey: k.Public()}
		if i == signingKeyIndex {
			signingKey = k
		}
	}
	if signingKey == nil {
		t.Fatalf("signingKeyIndex %d out of range for %d keys", signingKeyIndex, len(issuerKeys))
	}

	accessToken, _, err := token.IssueAccessToken(token.AccessTokenParams{
		// No "kid" header — ResolveAccessToken tries every candidate in
		// order regardless, the same as a real request where the
		// server's own kid isn't guaranteed to disambiguate (see
		// ResolveIssuerKeys' own KeyID hint, which this fake ignores by
		// always returning the same fixed set).
		Signer: signingKey, Algorithm: fapi.ES256,
		Issuer: testIssuer, Subject: "user-1", Audience: testIssuer,
		ClientID: "client-1", Now: time.Now(), Lifetime: 5 * time.Minute,
		Random: rand.Reader,
	})
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}

	jwt, err := resource.NewJWTAccessTokens(
		&fakeIssuerKeySource{set: keys.IssuerKeySet{Keys: issuerKeys}},
		issuerURL, testIssuer, fapi.ES256, 5*time.Minute, maxKeyCandidates,
	)
	if err != nil {
		t.Fatalf("NewJWTAccessTokens: %v", err)
	}
	return jwt, accessToken
}

// TestResolveAccessTokenRejectsKeyBeyondMaxCandidates covers the fix for
// the DoS-shaped TODO this MaxKeyCandidates field replaced: an
// IssuerKeySource returning more candidates than MaxKeyCandidates must
// not let ResolveAccessToken try one beyond the configured bound, even
// though it would otherwise validate successfully.
func TestResolveAccessTokenRejectsKeyBeyondMaxCandidates(t *testing.T) {
	jwt, accessToken := jwtAccessTokensWithCandidateKeys(t, 3, 3, 3) // signing key is the 4th (index 3), bound only allows the first 3
	if _, err := jwt.ResolveAccessToken(context.Background(), resource.ResolveAccessTokenRequest{Raw: accessToken, Now: time.Now()}); err == nil {
		t.Fatalf("ResolveAccessToken = nil error, want error (signing key sits beyond MaxKeyCandidates)")
	}
}

// TestResolveAccessTokenAcceptsKeyWithinMaxCandidates is the mirror
// case: the exact same signing key, positioned within the bound,
// verifies successfully — a regression guard against a fail-open bug
// (a loop that runs zero or too-few iterations must reject, never
// silently succeed with an unvalidated token).
func TestResolveAccessTokenAcceptsKeyWithinMaxCandidates(t *testing.T) {
	jwt, accessToken := jwtAccessTokensWithCandidateKeys(t, 3, 4, 3) // same shape, bound now covers all 4
	resolved, err := jwt.ResolveAccessToken(context.Background(), resource.ResolveAccessTokenRequest{Raw: accessToken, Now: time.Now()})
	if err != nil {
		t.Fatalf("ResolveAccessToken: %v", err)
	}
	if resolved.Subject != "user-1" {
		t.Fatalf("Subject = %q, want %q", resolved.Subject, "user-1")
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

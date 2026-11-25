package federation_test

import (
	"context"
	"crypto/tls"
	"net/http"
	"sync"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/federation"
	"github.com/idfoundry/fapigo/keys"
)

// expiryTestSkew is the MaxClockSkew the resolvers in this file allow.
const expiryTestSkew = 5 * time.Second

// settableClock is a federation.Clock a fetch can move while a
// resolution runs.
type settableClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *settableClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *settableClock) set(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = now
}

// onFetchTransport calls on with every request's path before sending it
// on: the time a fetch takes, as a test chooses it.
type onFetchTransport struct {
	base http.RoundTripper
	on   func(path string)
}

func (t onFetchTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.on(r.URL.Path)
	return t.base.RoundTrip(r)
}

// slowResolution is the fixture f's federation with a clock that moves
// to at, if at isn't zero, when path is fetched.
type slowResolution struct {
	f        *automaticRegistrationFixture
	clock    *settableClock
	fetcher  *fapihttp.Client
	resolver *federation.Resolver
}

func newSlowResolution(t *testing.T, f *automaticRegistrationFixture, path string, at *time.Time) *slowResolution {
	t.Helper()
	clock := &settableClock{now: f.now}
	transport := onFetchTransport{
		base: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: f.pool}},
		on: func(p string) {
			if p == path && !at.IsZero() {
				clock.set(*at)
			}
		},
	}
	fetcher, err := fapihttp.New(&http.Client{Transport: transport}, fapihttp.Config{
		MaxResponseBytes: 1 << 16, RequestTimeout: 5 * time.Second, MaxRedirects: 1,
		AllowLoopbackHTTP: true,
	})
	if err != nil {
		t.Fatalf("fapihttp.New: %v", err)
	}
	resolver, err := federation.NewResolver(federation.Config{
		TrustAnchors: []federation.TrustAnchor{{EntityID: f.taID, JWKS: f.taJWKS}},
		Limits:       federation.Limits{MaxPathLength: 5, MaxAuthorityHints: 5, MaxStatementLifetime: 2 * time.Hour, MaxClockSkew: expiryTestSkew},
	}, federation.Dependencies{HTTP: fetcher, Clock: clock})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	return &slowResolution{f: f, clock: clock, fetcher: fetcher, resolver: resolver}
}

// chainExpiry resolves f's RP once, with no time passing, for its Trust
// Chain's expiry.
func chainExpiry(t *testing.T, f *automaticRegistrationFixture) time.Time {
	t.Helper()
	var never time.Time
	resolved, err := newSlowResolution(t, f, "", &never).resolver.Resolve(context.Background(), f.rpID)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	return resolved.ExpiresAt
}

// TestResolveRefusesChainExpiredWhileResolving: Resolve verifies each
// statement at the time it started, so one whose last fetch (the Trust
// Anchor's Subordinate Statement about the RP) ends after the chain's
// exp has expired by the time it would return. It is refused, as
// starting the resolution then would have refused it; a chain still
// within MaxClockSkew of its exp then is not.
func TestResolveRefusesChainExpiredWhileResolving(t *testing.T) {
	f := setupAutomaticRegistrationFixture(t, rpMetadataBuilder(t))
	exp := chainExpiry(t, f)
	for name, tc := range map[string]struct {
		at      time.Time
		refused bool
	}{
		"long past exp":  {at: exp.Add(time.Hour), refused: true},
		"just past skew": {at: exp.Add(expiryTestSkew + time.Second), refused: true},
		"within skew":    {at: exp.Add(expiryTestSkew), refused: false},
		"before exp":     {at: exp.Add(-time.Second), refused: false},
		"no time passes": {refused: false},
	} {
		t.Run(name, func(t *testing.T) {
			at := tc.at
			slow := newSlowResolution(t, f, "/fetch", &at)
			resolved, err := slow.resolver.Resolve(context.Background(), f.rpID)
			if tc.refused {
				if err == nil {
					t.Fatalf("Resolve finishing at %v = chain expiring at %v, nil error; want the expired chain refused", slow.clock.Now(), resolved.ExpiresAt)
				}
				return
			}
			if err != nil {
				t.Fatalf("Resolve finishing at %v: %v, want the chain (exp %v, skew %v)", slow.clock.Now(), err, exp, expiryTestSkew)
			}
		})
	}
}

// TestAutomaticRegistrationRefusesChainExpiredWhileRegistering: a
// registration whose Trust Chain expires while it is built (here, while
// the RP's jwks_uri is fetched, after the chain has resolved) isn't
// handed to the request waiting on it: neither ResolveClient nor the key
// source answers with it, and nothing is cached.
func TestAutomaticRegistrationRefusesChainExpiredWhileRegistering(t *testing.T) {
	f := setupAutomaticRegistrationFixture(t, rpMetadataBuilderWithJWKSURI(t))
	f.rpMux.HandleFunc("/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksFor(t, "rp-oidc", f.rpOIDCKey))
	})
	exp := chainExpiry(t, f)
	for name, tc := range map[string]struct {
		at      time.Time
		refused bool
	}{
		"long past exp":  {at: exp.Add(time.Hour), refused: true},
		"just past skew": {at: exp.Add(expiryTestSkew + time.Second), refused: true},
		"within skew":    {at: exp.Add(expiryTestSkew), refused: false},
	} {
		t.Run(name, func(t *testing.T) {
			at := tc.at
			checkSlowRegistration(t, newSlowResolution(t, f, "/jwks.json", &at), tc.refused)
		})
	}
}

// TestAutomaticRegistrationRefusesChainExpiredWhileResolving is
// TestAutomaticRegistrationRefusesChainExpiredWhileRegistering with the
// chain expiring during the resolution itself.
func TestAutomaticRegistrationRefusesChainExpiredWhileResolving(t *testing.T) {
	f := setupAutomaticRegistrationFixture(t, rpMetadataBuilder(t))
	at := chainExpiry(t, f).Add(time.Hour)
	checkSlowRegistration(t, newSlowResolution(t, f, "/fetch", &at), true)
}

// checkSlowRegistration registers slow's RP through a fresh
// repository's ResolveClient and through its key source, and checks
// each is refused, with nothing cached, or answered, as refused says.
func checkSlowRegistration(t *testing.T, slow *slowResolution, refused bool) {
	t.Helper()
	id := fapi.ClientID(slow.f.rpID)
	newRepo := func() *federation.AutomaticClientRepository {
		slow.clock.set(slow.f.now)
		repo, err := federation.NewAutomaticClientRepository(alwaysFailsRepository{}, slow.resolver, slow.fetcher, validAutomaticRegistrationConfig(), slow.clock)
		if err != nil {
			t.Fatalf("NewAutomaticClientRepository: %v", err)
		}
		return repo
	}

	repo := newRepo()
	client, err := repo.ResolveClient(context.Background(), id)
	_, _, cached := federation.CachedChainPosition(repo, id)
	if refused && (err == nil || cached) {
		t.Fatalf("ResolveClient finishing at %v = (%q, %v), cached %v; want the expired chain's registration refused and not cached", slow.clock.Now(), client.ID(), err, cached)
	}
	if !refused && err != nil {
		t.Fatalf("ResolveClient finishing at %v: %v, want the client registered", slow.clock.Now(), err)
	}

	src, err := federation.NewAutomaticClientKeySource(alwaysFailsKeySource{}, newRepo())
	if err != nil {
		t.Fatalf("NewAutomaticClientKeySource: %v", err)
	}
	set, err := src.ResolveVerificationKeys(context.Background(), keys.ClientKeyRequest{ClientID: id, Algorithm: fapi.ES256})
	if refused && (err == nil || len(set.Keys) != 0) {
		t.Fatalf("ResolveVerificationKeys finishing at %v = %d keys, %v; want the expired chain's keys refused", slow.clock.Now(), len(set.Keys), err)
	}
	if !refused && (err != nil || len(set.Keys) == 0) {
		t.Fatalf("ResolveVerificationKeys finishing at %v = %d keys, %v; want the RP's key", slow.clock.Now(), len(set.Keys), err)
	}
}

package federation_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/federation"
	intfed "github.com/idfoundry/fapigo/internal/federation"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// hintTarget is a TLS server counting every request it receives, for
// entity configurations to name as authority_hints.
func hintTarget(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		http.NotFound(w, nil)
	}))
	t.Cleanup(ts.Close)
	return ts, &hits
}

func resolverWithHints(t *testing.T, hints []string, maxHints int, servers ...*httptest.Server) (*federation.Resolver, string) {
	t.Helper()
	key := generateKey(t)
	now := time.Now()
	entityID, ts := singleEntityServer(t, func(id string) string {
		token, err := intfed.Create(intfed.CreateParams{
			Signer: key, Algorithm: fapi.ES256, KeyID: "k",
			Issuer: id, Subject: id, Now: now, Lifetime: time.Hour, JWKS: jwksFor(t, "k", key),
			AuthorityHints: hints,
		})
		if err != nil {
			t.Fatalf("intfed.Create: %v", err)
		}
		return token
	}, nil)
	r, err := federation.NewResolver(federation.Config{
		TrustAnchors: []federation.TrustAnchor{{EntityID: "https://ta.example.org", JWKS: jwksFor(t, "a", generateKey(t))}},
		Limits:       federation.Limits{MaxPathLength: 5, MaxAuthorityHints: maxHints, MaxStatementLifetime: 2 * time.Hour, MaxClockSkew: 5 * time.Second},
	}, federation.Dependencies{HTTP: fetcherFor(t, append(servers, ts)...), Clock: fixedClock{now: now}})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	return r, entityID
}

// TestResolveRejectsTooManyAuthorityHints checks that an entity listing
// more authority_hints than Limits.MaxAuthorityHints is rejected before
// any of them is fetched, so one Resolve call can't be turned into an
// arbitrary number of outbound requests.
func TestResolveRejectsTooManyAuthorityHints(t *testing.T) {
	target, hits := hintTarget(t)
	hints := []string{target.URL + "/a", target.URL + "/b", target.URL + "/c"}

	r, entityID := resolverWithHints(t, hints, 2, target)
	_, err := r.Resolve(context.Background(), entityID)
	if err == nil || !strings.Contains(err.Error(), "authority_hints, more than the configured limit") {
		t.Fatalf("Resolve = %v, want the authority_hints limit error", err)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("hint target received %d requests, want 0", n)
	}

	// At the limit, every hint is still tried.
	r, entityID = resolverWithHints(t, hints, 3, target)
	if _, err := r.Resolve(context.Background(), entityID); err == nil || strings.Contains(err.Error(), "configured limit") {
		t.Fatalf("Resolve(at limit) = %v, want an unreachable-superior error", err)
	}
	if n := hits.Load(); n != 3 {
		t.Fatalf("hint target received %d requests, want 3", n)
	}
}

// TestAutomaticRegistrationSharesConcurrentResolution checks that
// concurrent requests naming the same unknown client_id share one Trust
// Chain resolution instead of each fetching the chain themselves.
func TestAutomaticRegistrationSharesConcurrentResolution(t *testing.T) {
	var fetches atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		once.Do(func() { close(started) })
		<-release
		http.NotFound(w, nil)
	}))
	t.Cleanup(ts.Close)

	resolver, err := federation.NewResolver(federation.Config{
		TrustAnchors: []federation.TrustAnchor{{EntityID: "https://ta.example.org", JWKS: jwksFor(t, "a", generateKey(t))}},
		Limits:       federation.Limits{MaxPathLength: 5, MaxAuthorityHints: 5, MaxStatementLifetime: 2 * time.Hour, MaxClockSkew: 5 * time.Second},
	}, federation.Dependencies{HTTP: fetcherFor(t, ts), Clock: federation.SystemClock{}})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	repo, err := federation.NewAutomaticClientRepository(memstore.NewClientRepository(nil), resolver, fetcherFor(t, ts),
		federation.AutomaticRegistrationConfig{AllowedScopes: []string{"openid"}, MaxCacheAge: time.Minute}, federation.SystemClock{})
	if err != nil {
		t.Fatalf("NewAutomaticClientRepository: %v", err)
	}

	const callers = 8
	id := fapi.ClientID(ts.URL)
	errs := make(chan error, callers)
	go func() {
		_, err := repo.ResolveClient(context.Background(), id)
		errs <- err
	}()
	<-started
	for i := 1; i < callers; i++ {
		go func() {
			_, err := repo.ResolveClient(context.Background(), id)
			errs <- err
		}()
	}
	time.Sleep(100 * time.Millisecond) // let the other callers join the in-flight resolution
	close(release)
	for i := 0; i < callers; i++ {
		if err := <-errs; err == nil {
			t.Fatal("ResolveClient = nil error, want the entity configuration fetch failure")
		}
	}
	if n := fetches.Load(); n != 1 {
		t.Fatalf("entity configuration fetched %d times, want 1", n)
	}
}

package keys

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"
)

// testP256JWK returns a minimal ES256 JWK Set document JSON containing
// one key with the given kid.
func testP256JWK(t *testing.T, kid string) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	x := base64.RawURLEncoding.EncodeToString(priv.X.FillBytes(make([]byte, 32)))
	y := base64.RawURLEncoding.EncodeToString(priv.Y.FillBytes(make([]byte, 32)))
	return fmt.Sprintf(`{"keys":[{"kty":"EC","crv":"P-256","x":%q,"y":%q,"kid":%q,"alg":"ES256","use":"sig"}]}`, x, y, kid)
}

func testFetcher(t *testing.T, ts *httptest.Server) *fapihttp.Client {
	t.Helper()
	c, err := fapihttp.New(ts.Client(), fapihttp.Config{
		MaxResponseBytes:  1 << 16,
		RequestTimeout:    5 * time.Second,
		MaxRedirects:      1,
		AllowLoopbackHTTP: true,
	})
	if err != nil {
		t.Fatalf("fapihttp.New: %v", err)
	}
	return c
}

// manualClock is a test-controlled clock, safe for concurrent use, so
// H-1's rate-limit and single-flight behavior can be tested
// deterministically instead of racing real time.
type manualClock struct {
	mu  sync.Mutex
	now time.Time
}

func newManualClock() *manualClock {
	return &manualClock{now: time.Unix(1700000000, 0)}
}

func (c *manualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *manualClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func TestUnknownKIDBurstCoalescesToSingleFetch(t *testing.T) {
	var fetches int32
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&fetches, 1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, testP256JWK(t, "kid-known"))
	}))
	defer ts.Close()

	jwksURI, err := fapi.ParseEndpointURL(ts.URL + "/jwks")
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	src, err := NewJWKSIssuerKeySource(testFetcher(t, ts), jwksURI, time.Hour)
	if err != nil {
		t.Fatalf("NewJWKSIssuerKeySource: %v", err)
	}
	// A stopped clock: every call arrives no later than the fetch.
	src.now = newManualClock().Now

	// No priming: the cache starts empty, so every one of these
	// concurrent, distinct-unknown-kid calls independently discovers a
	// cache miss and races to populate it via current's own
	// refreshSingleflight call — this is the single-flight coalescing
	// this test exercises. Once that first fetch completes, no call
	// forces another: the set each one misses in was fetched since it
	// arrived — so the total across all 50 must still be exactly one
	// fetch.
	const burst = 50
	var wg sync.WaitGroup
	wg.Add(burst)
	for i := 0; i < burst; i++ {
		go func(i int) {
			defer wg.Done()
			_, err := src.ResolveIssuerKeys(context.Background(), IssuerKeyRequest{
				Algorithm: fapi.ES256, KeyID: fmt.Sprintf("unknown-kid-%d", i),
			})
			if err != nil {
				t.Errorf("ResolveIssuerKeys(unknown-kid-%d): %v", i, err)
			}
		}(i)
	}
	wg.Wait()

	if got := atomic.LoadInt32(&fetches); got != 1 {
		t.Fatalf("fetches = %d, want 1 (burst of unknown kids should coalesce into a single upstream fetch)", got)
	}
}

func TestUnknownKIDRateLimited(t *testing.T) {
	var fetches int32
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&fetches, 1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, testP256JWK(t, "kid-known"))
	}))
	defer ts.Close()

	jwksURI, err := fapi.ParseEndpointURL(ts.URL + "/jwks")
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	clock := newManualClock()
	src, err := NewJWKSIssuerKeySource(testFetcher(t, ts), jwksURI, time.Hour, WithMinRefreshInterval(time.Minute))
	if err != nil {
		t.Fatalf("NewJWKSIssuerKeySource: %v", err)
	}
	src.now = clock.Now

	// No priming: the cache starts empty, so this first unknown-kid
	// lookup does the initial population fetch itself (via current);
	// the set it misses in was fetched for it, so no forced refresh.
	assertFetchesAfterMiss(t, src, "unknown-1", &fetches, 1)

	// Another unknown kid, on a set fetched before it arrived, forces
	// one refetch: a plain fetch doesn't count against the limit.
	clock.Advance(30 * time.Second)
	assertFetchesAfterMiss(t, src, "unknown-2", &fetches, 2)

	// A third, different unknown kid within minRefreshInterval of that
	// forced refetch must not force another.
	clock.Advance(59 * time.Second)
	assertFetchesAfterMiss(t, src, "unknown-3", &fetches, 2)

	// Once minRefreshInterval has elapsed, a further unknown kid is
	// allowed to force a new fetch.
	clock.Advance(time.Second)
	assertFetchesAfterMiss(t, src, "unknown-4", &fetches, 3)
}

// assertFetchesAfterMiss resolves the unknown kid against src and
// asserts that the upstream has then been fetched want times.
func assertFetchesAfterMiss(t *testing.T, src *JWKSIssuerKeySource, kid string, fetches *int32, want int32) {
	t.Helper()
	if _, err := src.ResolveIssuerKeys(context.Background(), IssuerKeyRequest{
		Algorithm: fapi.ES256, KeyID: kid,
	}); err != nil {
		t.Fatalf("ResolveIssuerKeys(%s): %v", kid, err)
	}
	if got := atomic.LoadInt32(fetches); got != want {
		t.Fatalf("fetches after a miss on %s = %d, want %d", kid, got, want)
	}
}

func TestNegativeCacheSuppressesRefetch(t *testing.T) {
	var fetches int32
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&fetches, 1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, testP256JWK(t, "kid-known"))
	}))
	defer ts.Close()

	jwksURI, err := fapi.ParseEndpointURL(ts.URL + "/jwks")
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	src, err := NewJWKSIssuerKeySource(testFetcher(t, ts), jwksURI, time.Hour, WithMinRefreshInterval(time.Minute))
	if err != nil {
		t.Fatalf("NewJWKSIssuerKeySource: %v", err)
	}

	// No priming: the cache starts empty, so the first of these two
	// identical-kid calls does the initial population fetch itself.
	for i := 0; i < 2; i++ {
		if _, err := src.ResolveIssuerKeys(context.Background(), IssuerKeyRequest{
			Algorithm: fapi.ES256, KeyID: "same-unknown-kid",
		}); err != nil {
			t.Fatalf("ResolveIssuerKeys[%d]: %v", i, err)
		}
	}
	if got := atomic.LoadInt32(&fetches); got != 1 {
		t.Fatalf("fetches = %d, want 1 (repeated miss on the same kid should not refetch)", got)
	}
}

// TestRotationStillResolvesAfterInterval: a rotated-in kid forces a
// refetch at once, however long the cache TTL; a second rotation within
// the minimum refresh interval of that forced refetch waits for the
// interval, then resolves.
func TestRotationStillResolvesAfterInterval(t *testing.T) {
	assertIssuerRotations(t, time.Hour, time.Minute, WithMinRefreshInterval(time.Minute))
}

// TestRotationResolvesWithDefaultOptions: the same with no options,
// where the minimum refresh interval used to default to the cache TTL
// and every TTL refresh reset it, so an unknown kid never forced a
// refetch (OIDC Core §10.1.1).
func TestRotationResolvesWithDefaultOptions(t *testing.T) {
	assertIssuerRotations(t, 15*time.Minute, defaultMinRefreshInterval)
}

// assertIssuerRotations drives two key rotations against a
// JWKSIssuerKeySource built with cacheTTL and opts, whose minimum
// refresh interval is interval.
func assertIssuerRotations(t *testing.T, cacheTTL, interval time.Duration, opts ...JWKSOption) {
	t.Helper()
	var kid atomic.Value
	kid.Store("kid-original")
	var fetches atomic.Int32
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, testP256JWK(t, kid.Load().(string)))
	}))
	defer ts.Close()

	jwksURI, err := fapi.ParseEndpointURL(ts.URL + "/jwks")
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	clock := newManualClock()
	src, err := NewJWKSIssuerKeySource(testFetcher(t, ts), jwksURI, cacheTTL, opts...)
	if err != nil {
		t.Fatalf("NewJWKSIssuerKeySource: %v", err)
	}
	src.now = clock.Now

	assertIssuerKeyCount(t, src, "kid-original", 1)
	kid.Store("kid-rotated")
	clock.Advance(time.Second)
	assertIssuerKeyCount(t, src, "kid-rotated", 1)
	if n := fetches.Load(); n != 2 {
		t.Fatalf("fetches after the first rotation = %d, want 2", n)
	}

	kid.Store("kid-rotated-again")
	clock.Advance(interval / 2)
	assertIssuerKeyCount(t, src, "kid-rotated-again", 0)
	clock.Advance(interval / 2)
	assertIssuerKeyCount(t, src, "kid-rotated-again", 1)
	if n := fetches.Load(); n != 3 {
		t.Fatalf("fetches after the second rotation = %d, want 3", n)
	}
}

// assertIssuerKeyCount asserts that src resolves want ES256 keys for kid.
func assertIssuerKeyCount(t *testing.T, src *JWKSIssuerKeySource, kid string, want int) {
	t.Helper()
	set, err := src.ResolveIssuerKeys(context.Background(), IssuerKeyRequest{Algorithm: fapi.ES256, KeyID: kid})
	if err != nil {
		t.Fatalf("ResolveIssuerKeys(%s): %v", kid, err)
	}
	if len(set.Keys) != want {
		t.Fatalf("ResolveIssuerKeys(%s) = %+v, want %d keys", kid, set.Keys, want)
	}
}

// TestTTLRefreshBackoffAfterFailure covers L-A: a cold or expired cache
// against a failing upstream must not issue one outbound fetch per
// caller — only one fetch per refreshBackoff window, until the upstream
// recovers.
func TestTTLRefreshBackoffAfterFailure(t *testing.T) {
	var fetches int32
	var failing atomic.Bool
	failing.Store(true)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&fetches, 1)
		if failing.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, testP256JWK(t, "kid-1"))
	}))
	defer ts.Close()

	jwksURI, err := fapi.ParseEndpointURL(ts.URL + "/jwks")
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	clock := newManualClock()
	src, err := NewJWKSIssuerKeySource(testFetcher(t, ts), jwksURI, time.Hour, WithRefreshBackoff(time.Minute))
	if err != nil {
		t.Fatalf("NewJWKSIssuerKeySource: %v", err)
	}
	src.now = clock.Now

	req := IssuerKeyRequest{Algorithm: fapi.ES256}

	if _, err := src.ResolveIssuerKeys(context.Background(), req); err == nil {
		t.Fatalf("ResolveIssuerKeys[cold, failing] = nil error, want error")
	}
	if got := atomic.LoadInt32(&fetches); got != 1 {
		t.Fatalf("fetches after first failure = %d, want 1", got)
	}

	// A second call within the backoff window must not issue another
	// fetch — it should fail fast with the remembered error.
	clock.Advance(30 * time.Second)
	if _, err := src.ResolveIssuerKeys(context.Background(), req); err == nil {
		t.Fatalf("ResolveIssuerKeys[within backoff] = nil error, want error")
	}
	if got := atomic.LoadInt32(&fetches); got != 1 {
		t.Fatalf("fetches within backoff window = %d, want 1 (no refetch)", got)
	}

	// Once refreshBackoff has elapsed, a new attempt is allowed even
	// though the upstream is still failing.
	clock.Advance(31 * time.Second)
	if _, err := src.ResolveIssuerKeys(context.Background(), req); err == nil {
		t.Fatalf("ResolveIssuerKeys[after backoff, still failing] = nil error, want error")
	}
	if got := atomic.LoadInt32(&fetches); got != 2 {
		t.Fatalf("fetches after backoff elapsed = %d, want 2", got)
	}

	// The upstream recovers; once backoff elapses again, the next call
	// succeeds and clears the remembered failure.
	failing.Store(false)
	clock.Advance(time.Minute + time.Second)
	set, err := src.ResolveIssuerKeys(context.Background(), req)
	if err != nil {
		t.Fatalf("ResolveIssuerKeys[recovered]: %v", err)
	}
	if len(set.Keys) != 1 || set.Keys[0].KeyID != "kid-1" {
		t.Fatalf("Keys = %+v, want one key with kid-1", set.Keys)
	}
}

// TestLeaderCancellationDoesNotPoisonWaiters covers L-B: a caller whose
// own context is cancelled must not deliver ctx.Err() to other callers
// coalesced onto the same in-flight refresh.
func TestLeaderCancellationDoesNotPoisonWaiters(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		<-release
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, testP256JWK(t, "kid-1"))
	}))
	defer ts.Close()

	jwksURI, err := fapi.ParseEndpointURL(ts.URL + "/jwks")
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	src, err := NewJWKSIssuerKeySource(testFetcher(t, ts), jwksURI, time.Hour)
	if err != nil {
		t.Fatalf("NewJWKSIssuerKeySource: %v", err)
	}

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderErr := make(chan error, 1)
	go func() {
		_, err := src.ResolveIssuerKeys(leaderCtx, IssuerKeyRequest{Algorithm: fapi.ES256})
		leaderErr <- err
	}()

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("leader fetch did not start in time")
	}

	waiterResult := make(chan IssuerKeySet, 1)
	waiterErr := make(chan error, 1)
	go func() {
		set, err := src.ResolveIssuerKeys(context.Background(), IssuerKeyRequest{Algorithm: fapi.ES256})
		waiterResult <- set
		waiterErr <- err
	}()

	// Give the waiter goroutine time to reach refreshSingleflight and
	// coalesce onto the leader's in-flight call before cancelling the
	// leader — release stays closed until after that cancellation is
	// confirmed below, so the fetch cannot complete out from under it.
	time.Sleep(50 * time.Millisecond)
	cancelLeader()

	select {
	case err := <-leaderErr:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("leader error = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("leader did not observe its own cancellation in time")
	}

	close(release)

	select {
	case err := <-waiterErr:
		if err != nil {
			t.Fatalf("waiter error = %v, want nil (leader's cancellation must not poison it)", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waiter did not complete in time")
	}
	if set := <-waiterResult; len(set.Keys) != 1 || set.Keys[0].KeyID != "kid-1" {
		t.Fatalf("waiter Keys = %+v, want one key with kid-1", set.Keys)
	}
}

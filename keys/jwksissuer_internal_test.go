package keys

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
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

	// No priming: the cache starts empty, so every one of these
	// concurrent, distinct-unknown-kid calls independently discovers a
	// cache miss and races to populate it via currentKeys' own
	// refreshSingleflight call — this is the single-flight coalescing
	// this test exercises. Once that first fetch completes, each call's
	// own forced-refresh attempt (the kid still won't match) is in turn
	// suppressed by minRefreshInterval, since it was just satisfied by
	// the same fetch a moment ago — so the total across all 50 must
	// still be exactly one fetch.
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
	// lookup does the initial population fetch itself (via
	// currentKeys), which also stamps lastAttempt.
	if _, err := src.ResolveIssuerKeys(context.Background(), IssuerKeyRequest{
		Algorithm: fapi.ES256, KeyID: "unknown-1",
	}); err != nil {
		t.Fatalf("ResolveIssuerKeys(unknown-1): %v", err)
	}
	if got := atomic.LoadInt32(&fetches); got != 1 {
		t.Fatalf("fetches after first miss = %d, want 1", got)
	}

	// A second, different unknown kid within minRefreshInterval must not
	// force another fetch.
	clock.Advance(30 * time.Second)
	if _, err := src.ResolveIssuerKeys(context.Background(), IssuerKeyRequest{
		Algorithm: fapi.ES256, KeyID: "unknown-2",
	}); err != nil {
		t.Fatalf("ResolveIssuerKeys(unknown-2): %v", err)
	}
	if got := atomic.LoadInt32(&fetches); got != 1 {
		t.Fatalf("fetches after second miss within interval = %d, want 1 (rate limit not enforced)", got)
	}

	// Once minRefreshInterval has elapsed, a further unknown kid is
	// allowed to force a new fetch.
	clock.Advance(31 * time.Second)
	if _, err := src.ResolveIssuerKeys(context.Background(), IssuerKeyRequest{
		Algorithm: fapi.ES256, KeyID: "unknown-3",
	}); err != nil {
		t.Fatalf("ResolveIssuerKeys(unknown-3): %v", err)
	}
	if got := atomic.LoadInt32(&fetches); got != 2 {
		t.Fatalf("fetches after interval elapsed = %d, want 2", got)
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

func TestRotationStillResolvesAfterInterval(t *testing.T) {
	var newKID atomic.Bool
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if newKID.Load() {
			fmt.Fprint(w, testP256JWK(t, "kid-rotated"))
		} else {
			fmt.Fprint(w, testP256JWK(t, "kid-original"))
		}
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

	if _, err := src.ResolveIssuerKeys(context.Background(), IssuerKeyRequest{
		Algorithm: fapi.ES256, KeyID: "kid-original",
	}); err != nil {
		t.Fatalf("prime: %v", err)
	}

	// The priming resolve above already stamped lastAttempt at clock's
	// current value, so this immediate query for the (now rotated) kid
	// is still within minRefreshInterval and must not force a refresh.
	newKID.Store(true)
	set, err := src.ResolveIssuerKeys(context.Background(), IssuerKeyRequest{
		Algorithm: fapi.ES256, KeyID: "kid-rotated",
	})
	if err != nil {
		t.Fatalf("ResolveIssuerKeys(kid-rotated, within interval): %v", err)
	}
	if len(set.Keys) != 0 {
		t.Fatalf("Keys = %+v, want none yet (forced refresh should still be rate-limited)", set.Keys)
	}

	// After minRefreshInterval elapses, the same kid resolves.
	clock.Advance(2 * time.Minute)
	set, err = src.ResolveIssuerKeys(context.Background(), IssuerKeyRequest{
		Algorithm: fapi.ES256, KeyID: "kid-rotated",
	})
	if err != nil {
		t.Fatalf("ResolveIssuerKeys(kid-rotated, after interval): %v", err)
	}
	if len(set.Keys) != 1 || set.Keys[0].KeyID != "kid-rotated" {
		t.Fatalf("Keys = %+v, want one key with kid-rotated", set.Keys)
	}
}

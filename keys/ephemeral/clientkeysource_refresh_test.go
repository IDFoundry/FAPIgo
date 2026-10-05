package ephemeral

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/keys"
)

// refreshHarness is a ClientKeySource over a counting jwks_uri, with a
// clock the test moves.
type refreshHarness struct {
	src     *ClientKeySource
	fetches *atomic.Int32
	fail    *atomic.Bool
	now     *time.Time
}

func newRefreshHarness(t *testing.T, opts ...Option) refreshHarness {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jwk := p256JWKJSON(t, &priv.PublicKey, "kid-1", "ES256")
	var fetches atomic.Int32
	var fail atomic.Bool
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		if fail.Load() {
			http.Error(w, "down", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"keys":[%s]}`, jwk)
	}))
	t.Cleanup(ts.Close)
	fetcher, err := fapihttp.New(ts.Client(), fapihttp.Config{
		MaxResponseBytes: 1 << 16, RequestTimeout: 5 * time.Second, MaxRedirects: 1,
		AllowLoopbackHTTP: true,
	})
	if err != nil {
		t.Fatalf("fapihttp.New: %v", err)
	}
	if opts == nil {
		opts = []Option{WithCacheTTL(time.Minute), WithMinRefreshInterval(10 * time.Second)}
	}
	src, err := NewClientKeySource(fetcher, []ClientKeySpec{{ClientID: "client-1", JWKSURI: ts.URL + "/jwks"}}, opts...)
	if err != nil {
		t.Fatalf("NewClientKeySource: %v", err)
	}
	now := time.Now()
	src.now = func() time.Time { return now }
	return refreshHarness{src: src, fetches: &fetches, fail: &fail, now: &now}
}

func (h refreshHarness) resolve(kid string) (keys.VerificationKeySet, error) {
	return h.src.ResolveVerificationKeys(context.Background(), keys.ClientKeyRequest{
		ClientID: "client-1", Algorithm: fapi.ES256, KeyID: kid,
	})
}

// TestClientKeySourceBoundsUnknownKeyIDRefetches: a kid is taken from an
// unverified JWT header, so a stream of distinct unknown kids within
// the minimum refresh interval forces no fetch beyond the first.
func TestClientKeySourceBoundsUnknownKeyIDRefetches(t *testing.T) {
	h := newRefreshHarness(t)
	if _, err := h.resolve("kid-1"); err != nil {
		t.Fatalf("resolve(kid-1): %v", err)
	}
	for i := range 50 {
		*h.now = h.now.Add(100 * time.Millisecond)
		set, err := h.resolve(fmt.Sprintf("attacker-%d", i))
		if err != nil || len(set.Keys) != 0 {
			t.Fatalf("resolve(unknown kid) = %+v, %v; want no keys, no error", set.Keys, err)
		}
	}
	if got := h.fetches.Load(); got != 1 {
		t.Fatalf("fetches = %d after 50 unknown kids within the interval, want 1", got)
	}
}

// TestClientKeySourceConcurrentMissesShareOneFetch: callers that all
// miss once the interval has passed wait for one fetch rather than each
// making their own.
func TestClientKeySourceConcurrentMissesShareOneFetch(t *testing.T) {
	h := newRefreshHarness(t)
	if _, err := h.resolve("kid-1"); err != nil {
		t.Fatalf("resolve(kid-1): %v", err)
	}
	*h.now = h.now.Add(11 * time.Second)
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = h.resolve(fmt.Sprintf("unknown-%d", i))
		}()
	}
	wg.Wait()
	if got := h.fetches.Load(); got != 2 {
		t.Fatalf("fetches = %d after 20 concurrent misses, want 2 (the first lookup plus one shared refetch)", got)
	}
}

// TestClientKeySourceBacksOffAfterAFailedFetch: a failing jwks_uri isn't
// fetched again on every request — the failure is returned until the
// backoff has passed — and a fresh cached set keeps being used meanwhile.
func TestClientKeySourceBacksOffAfterAFailedFetch(t *testing.T) {
	t.Run("no cached set", func(t *testing.T) {
		h := newRefreshHarness(t)
		h.fail.Store(true)
		for range 3 {
			if _, err := h.resolve(""); err == nil {
				t.Fatal("resolve against a failing jwks_uri = nil error, want error")
			}
			*h.now = h.now.Add(time.Second)
		}
		if got := h.fetches.Load(); got != 1 {
			t.Fatalf("fetches = %d within the backoff, want 1", got)
		}
		*h.now = h.now.Add(5 * time.Second)
		h.fail.Store(false)
		if _, err := h.resolve("kid-1"); err != nil {
			t.Fatalf("resolve after the backoff: %v", err)
		}
		if got := h.fetches.Load(); got != 2 {
			t.Fatalf("fetches = %d after the backoff, want 2", got)
		}
	})
	t.Run("fresh cached set", func(t *testing.T) {
		h := newRefreshHarness(t)
		if _, err := h.resolve("kid-1"); err != nil {
			t.Fatalf("resolve(kid-1): %v", err)
		}
		h.fail.Store(true)
		*h.now = h.now.Add(11 * time.Second)
		if _, err := h.resolve("rotated"); err == nil {
			t.Fatal("resolve(unknown kid) with a failing refetch = nil error, want the fetch error")
		}
		*h.now = h.now.Add(time.Second)
		set, err := h.resolve("kid-1")
		if err != nil || len(set.Keys) != 1 {
			t.Fatalf("resolve(kid-1) during the backoff = %+v, %v; want the cached key", set.Keys, err)
		}
		if _, err := h.resolve("rotated"); err != nil {
			t.Fatalf("resolve(unknown kid) during the backoff = %v, want the cached set without a fetch", err)
		}
		if got := h.fetches.Load(); got != 2 {
			t.Fatalf("fetches = %d, want 2 (no retry within the backoff)", got)
		}
	})
}

func TestNewClientKeySourceRejectsNonPositiveCacheTTL(t *testing.T) {
	if _, err := NewClientKeySource(nil, nil, WithCacheTTL(0)); err == nil {
		t.Fatal("NewClientKeySource(WithCacheTTL(0)) = nil error, want error")
	}
}

// TestClientKeySourceMinRefreshIntervalDefaultsToCacheTTL: without
// WithMinRefreshInterval, an unknown kid forces at most one refetch per
// cache TTL, as keys.JWKSIssuerKeySource's own default does.
func TestClientKeySourceMinRefreshIntervalDefaultsToCacheTTL(t *testing.T) {
	h := newRefreshHarness(t, WithCacheTTL(time.Minute))
	if _, err := h.resolve("kid-1"); err != nil {
		t.Fatalf("resolve(kid-1): %v", err)
	}
	*h.now = h.now.Add(59 * time.Second)
	if _, err := h.resolve("unknown"); err != nil {
		t.Fatalf("resolve(unknown): %v", err)
	}
	if got := h.fetches.Load(); got != 1 {
		t.Fatalf("fetches = %d for an unknown kid within the cache TTL, want 1", got)
	}
	*h.now = h.now.Add(2 * time.Second)
	if _, err := h.resolve("unknown"); err != nil {
		t.Fatalf("resolve(unknown): %v", err)
	}
	if got := h.fetches.Load(); got != 2 {
		t.Fatalf("fetches = %d once the cache TTL has passed, want 2", got)
	}
}

// TestClientKeySourceCallerCancellationDoesNotFailOthers: a caller
// giving up mid-request (its context cancelled) mustn't be recorded as
// the client's fetch failure, which would refuse every other request
// for that client for the backoff without fetching.
func TestClientKeySourceCallerCancellationDoesNotFailOthers(t *testing.T) {
	h := newRefreshHarness(t)
	if _, err := h.resolve("kid-1"); err != nil {
		t.Fatalf("resolve(kid-1): %v", err)
	}
	*h.now = h.now.Add(2 * time.Minute) // past the cache TTL

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := h.src.ResolveVerificationKeys(cancelled, keys.ClientKeyRequest{
		ClientID: "client-1", Algorithm: fapi.ES256, KeyID: "kid-1",
	}); err == nil {
		t.Fatal("resolve with a cancelled context = nil error, want the context's error")
	}

	set, err := h.resolve("kid-1")
	if err != nil || len(set.Keys) != 1 {
		t.Fatalf("resolve(kid-1) after another caller cancelled = %+v, %v; want the key", set.Keys, err)
	}
}

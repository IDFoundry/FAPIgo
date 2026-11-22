package keys

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
)

// TestJWKSCacheBoundsNegativeKeyIDs: the negative cache of unknown kids
// never grows past maxNegativeKIDs, and expired entries make room for
// new ones.
func TestJWKSCacheBoundsNegativeKeyIDs(t *testing.T) {
	clock := newManualClock()
	c := newJWKSCache(jwksCacheTiming{cacheTTL: time.Hour}.withDefaults(), clock.Now, func(context.Context) ([]IssuerKey, error) { return nil, nil })
	for i := range maxNegativeKIDs + 10 {
		c.rememberMiss(negativeKIDKey(fmt.Sprintf("kid-%d", i)))
	}
	if n := len(c.negativeKIDs); n != maxNegativeKIDs {
		t.Fatalf("negative cache holds %d kids, want %d", n, maxNegativeKIDs)
	}
	if c.reserveForcedRefresh(negativeKIDKey("kid-0"), clock.Now()) {
		t.Fatalf("a negative-cached kid may force a refresh")
	}
	clock.Advance(2 * time.Hour)
	c.rememberMiss(negativeKIDKey("later"))
	if n := len(c.negativeKIDs); n != 1 {
		t.Fatalf("negative cache holds %d kids after expiry, want only the new one", n)
	}
}

// longKIDLength is about the longest kid a JWT within
// jose.DefaultMaxCompactBytes can carry: a client assertion's, with a
// short client_id, minimal claims and a one-byte signature.
const longKIDLength = 12210

// longKID is the i'th of distinct kids longKIDLength bytes long.
func longKID(i int) string {
	prefix := fmt.Sprintf("kid-%07d-", i)
	return prefix + strings.Repeat("A", longKIDLength-len(prefix))
}

// checkNegativeKIDsFullAndBounded fails t unless c's negative cache
// remembers maxNegativeKIDs kids in keys of a digest's size each,
// however long the kids.
func checkNegativeKIDsFullAndBounded[V any](t *testing.T, c *jwksCache[V]) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	keyBytes := 0
	for k := range c.negativeKIDs {
		keyBytes += len(k)
	}
	if n := len(c.negativeKIDs); n != maxNegativeKIDs {
		t.Fatalf("negative cache remembers %d kids, want %d", n, maxNegativeKIDs)
	}
	if limit := maxNegativeKIDs * sha256.Size; keyBytes > limit {
		t.Fatalf("negative cache keys take %d bytes for %d-byte kids, want at most %d", keyBytes, longKIDLength, limit)
	}
}

// TestJWKSCacheBoundsNegativeKeyIDBytes: the negative cache full of
// kids as long as a JWT can carry takes no more memory than full of
// short ones, and a long kid it remembers still holds back a forced
// refresh for itself.
func TestJWKSCacheBoundsNegativeKeyIDBytes(t *testing.T) {
	clock := newManualClock()
	c := newJWKSCache(jwksCacheTiming{cacheTTL: time.Hour}.withDefaults(), clock.Now, func(context.Context) ([]IssuerKey, error) { return nil, nil })
	for i := range maxNegativeKIDs + 10 {
		c.rememberMiss(negativeKIDKey(longKID(i)))
	}
	checkNegativeKIDsFullAndBounded(t, c)
	if c.reserveForcedRefresh(negativeKIDKey(longKID(0)), clock.Now()) {
		t.Fatal("a negative-cached long kid may force a refresh")
	}
}

// TestJWKSCacheTellsLongKeyIDsApart: two kids that differ only in their
// last byte are remembered apart, so a miss on one never holds back the
// forced refresh for the other, a key rotated in under it later.
func TestJWKSCacheTellsLongKeyIDsApart(t *testing.T) {
	clock := newManualClock()
	c := newJWKSCache(jwksCacheTiming{cacheTTL: time.Hour}.withDefaults(), clock.Now, func(context.Context) ([]IssuerKey, error) { return nil, nil })
	prefix := strings.Repeat("B", longKIDLength-1)
	c.rememberMiss(negativeKIDKey(prefix + "1"))
	if !c.reserveForcedRefresh(negativeKIDKey(prefix+"2"), clock.Now()) {
		t.Fatalf("a kid sharing a %d-byte prefix with a negative-cached one may not force a refresh", len(prefix))
	}
}

// clientCache is client id's jwks_uri cache in src.
func clientCache(t *testing.T, src *ClientJWKSSource, id fapi.ClientID) *jwksCache[clientKeySet] {
	t.Helper()
	src.mu.Lock()
	defer src.mu.Unlock()
	e, ok := src.entries[id]
	if !ok || e.cache == nil {
		t.Fatalf("no jwks_uri cache for client %q", id)
	}
	return e.cache
}

// TestClientJWKSSourceBoundsLongKeyIDsSentSlowly: one unknown kid of a
// JWT's greatest length each minimum refresh interval, each forcing a
// refetch that still misses, fills a client's negative cache with no
// burst at all, and it takes no more memory full of such kids than of
// short ones.
func TestClientJWKSSourceBoundsLongKeyIDsSentSlowly(t *testing.T) {
	doc, _ := es256JWKS(t, "real-key")
	src, srv, _ := newURISource(t, map[fapi.ClientID][]byte{"a": doc})
	clock := newManualClock()
	src.now = clock.Now
	if got, err := resolveES256(t, src, "a", "real-key"); err != nil || len(got) != 1 {
		t.Fatalf("real-key: got %d keys, err %v", len(got), err)
	}
	for i := range maxNegativeKIDs {
		clock.Advance(defaultMinRefreshInterval + time.Second)
		if got, err := resolveES256(t, src, "a", longKID(i)); err != nil || len(got) != 0 {
			t.Fatalf("unknown kid %d: got %d keys, err %v", i, len(got), err)
		}
	}
	if n := srv.fetchCount("/a"); n != maxNegativeKIDs+1 {
		t.Fatalf("fetches = %d, want %d: the first, then one forced by each unknown kid", n, maxNegativeKIDs+1)
	}
	checkNegativeKIDsFullAndBounded(t, clientCache(t, src, "a"))
}

// resolveLongKeyIDsAtOnce resolves 1500 distinct unknown kids of a
// JWT's greatest length concurrently through resolve, which returns how
// many keys it found, failing t unless each finds none without error.
func resolveLongKeyIDsAtOnce(t *testing.T, resolve func(kid string) (int, error)) {
	t.Helper()
	const burst = 1500 // well past maxNegativeKIDs
	var wg sync.WaitGroup
	var unexpected atomic.Int32
	for i := range burst {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if n, err := resolve(longKID(i)); err != nil || n != 0 {
				unexpected.Add(1)
			}
		}()
	}
	wg.Wait()
	if n := unexpected.Load(); n != 0 {
		t.Fatalf("%d resolutions of an unknown kid failed or found a key", n)
	}
}

// TestClientJWKSSourceBoundsLongKeyIDsInABurst: a burst of distinct
// unknown kids of a JWT's greatest length, arriving no later than the
// client's set was fetched (the clock stopped at the fetch), is
// negative-cached by the arrival-time rule without another fetch, and
// the cache, full of them, takes no more memory than full of short kids.
func TestClientJWKSSourceBoundsLongKeyIDsInABurst(t *testing.T) {
	doc, _ := es256JWKS(t, "real-key")
	src, srv, _ := newURISource(t, map[fapi.ClientID][]byte{"a": doc})
	src.now = newManualClock().Now
	if got, err := resolveES256(t, src, "a", "real-key"); err != nil || len(got) != 1 {
		t.Fatalf("real-key: got %d keys, err %v", len(got), err)
	}
	resolveLongKeyIDsAtOnce(t, func(kid string) (int, error) {
		got, err := resolveES256(t, src, "a", kid)
		return len(got), err
	})
	if n := srv.fetchCount("/a"); n != 1 {
		t.Fatalf("fetches = %d, want 1", n)
	}
	checkNegativeKIDsFullAndBounded(t, clientCache(t, src, "a"))
}

// TestJWKSIssuerKeySourceBoundsLongKeyIDs is the burst for a
// JWKSIssuerKeySource, whose kids come from the access tokens or ID
// tokens it verifies.
func TestJWKSIssuerKeySourceBoundsLongKeyIDs(t *testing.T) {
	doc := testP256JWK(t, "kid-known")
	var fetches atomic.Int32
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, doc)
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
	src.now = newManualClock().Now
	resolve := func(kid string) (int, error) {
		set, err := src.ResolveIssuerKeys(context.Background(), IssuerKeyRequest{Algorithm: fapi.ES256, KeyID: kid})
		return len(set.Keys), err
	}
	if n, err := resolve("kid-known"); err != nil || n != 1 {
		t.Fatalf("kid-known: got %d keys, err %v", n, err)
	}
	resolveLongKeyIDsAtOnce(t, resolve)
	if n := fetches.Load(); n != 1 {
		t.Fatalf("fetches = %d, want 1", n)
	}
	checkNegativeKIDsFullAndBounded(t, src.cache)
}

// TestClientJWKSSourceDropsExpiredClientsFirst: past the bound, a
// client whose cached set has expired is dropped before a fresh one.
func TestClientJWKSSourceDropsExpiredClientsFirst(t *testing.T) {
	docA, _ := es256JWKS(t, "k")
	docB, _ := es256JWKS(t, "k")
	docC, _ := es256JWKS(t, "k")
	src, srv, _ := newURISource(t, map[fapi.ClientID][]byte{"a": docA, "b": docB, "c": docC}, WithClientJWKSMaxClients(2), WithClientJWKSCacheTTL(time.Minute))
	clock := newManualClock()
	src.now = clock.Now
	for _, id := range []fapi.ClientID{"a", "b"} {
		if _, err := resolveES256(t, src, id, "k"); err != nil {
			t.Fatalf("client %q: %v", id, err)
		}
	}
	clock.Advance(2 * time.Minute)
	if _, err := resolveES256(t, src, "b", "k"); err != nil { // b refetched: fresh again
		t.Fatalf("client b: %v", err)
	}
	if _, err := resolveES256(t, src, "c", "k"); err != nil {
		t.Fatalf("client c: %v", err)
	}
	src.mu.Lock()
	_, keptA := src.entries["a"]
	_, keptB := src.entries["b"]
	src.mu.Unlock()
	if keptA || !keptB {
		t.Fatalf("kept a=%v b=%v; want the expired a dropped and the fresh b kept", keptA, keptB)
	}
	if n := srv.fetchCount("/b"); n != 2 {
		t.Fatalf("fetches of b = %d, want 2", n)
	}
}

// TestClientJWKSSourceRefusesUnusableFetchedJWKS: a jwks_uri serving a
// JWK Set with no usable key fails closed.
func TestClientJWKSSourceRefusesUnusableFetchedJWKS(t *testing.T) {
	src, _, _ := newURISource(t, map[fapi.ClientID][]byte{"a": []byte(`{"keys":[]}`)})
	if _, err := resolveES256(t, src, "a", ""); err == nil {
		t.Fatalf("a jwks_uri serving no usable key: no error")
	}
}

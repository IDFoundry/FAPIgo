package keys

import (
	"context"
	"fmt"
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
		c.rememberMiss(fmt.Sprintf("kid-%d", i))
	}
	if n := len(c.negativeKIDs); n != maxNegativeKIDs {
		t.Fatalf("negative cache holds %d kids, want %d", n, maxNegativeKIDs)
	}
	if c.shouldForceRefresh("kid-0") {
		t.Fatalf("a negative-cached kid may force a refresh")
	}
	clock.Advance(2 * time.Hour)
	c.rememberMiss("later")
	if n := len(c.negativeKIDs); n != 1 {
		t.Fatalf("negative cache holds %d kids after expiry, want only the new one", n)
	}
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

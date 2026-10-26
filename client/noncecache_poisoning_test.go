package client_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
)

// TestProtectedResourceNonceCacheResistsPoisoning: resource nonces are
// cached per origin, so another resource on the same origin (a
// co-tenant path) could hand out one that every later request to the
// origin carries. An oversized one would make an honest resource server
// answer 431, never a challenge, forever. A nonce that isn't 1*NQCHAR of
// at most 1024 bytes is never cached, and a non-challenge 4xx forgets
// whatever was.
func TestProtectedResourceNonceCacheResistsPoisoning(t *testing.T) {
	ctx := context.Background()
	huge := strings.Repeat("n", 1100*1024)
	var (
		mu        sync.Mutex
		goodHits  int
		goodNonce []string
	)
	mux := http.NewServeMux()
	mux.HandleFunc("/tenant-evil/huge", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("DPoP-Nonce", huge)
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/tenant-evil/forbidden", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("DPoP-Nonce", "planted-on-error")
		w.WriteHeader(http.StatusForbidden)
	})
	mux.HandleFunc("/tenant-good/api", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		goodHits++
		goodNonce = append(goodNonce, nonceClaim(t, r))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})
	rs := httptest.NewServer(mux) // http.Server's default MaxHeaderBytes, 1 MiB
	t.Cleanup(rs.Close)
	c := newResourceTestClient(t, rs, nil)
	rc := c.ClientCredentialsResource(client.ClientCredentialsTokenResult{AccessToken: fapi.NewSecret("at")})
	do := func(path string) int {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rs.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		res, err := rc.Do(ctx, req)
		if err != nil {
			t.Fatalf("Do(%s): %v", path, err)
		}
		_ = res.Body.Close()
		return res.StatusCode
	}

	rsURL, _ := url.Parse(rs.URL)
	rc.UseDPoPNonce(ctx, rsURL, huge)
	do("/tenant-evil/huge")
	do("/tenant-evil/forbidden")
	for i := 0; i < 3; i++ {
		if status := do("/tenant-good/api"); status != http.StatusOK {
			t.Fatalf("good call %d after poisoning: HTTP %d", i, status)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if goodHits != 3 {
		t.Fatalf("honest handler hits = %d, want 3", goodHits)
	}
	for i, n := range goodNonce {
		if n != "" {
			t.Errorf("good call %d presented nonce %.20q…", i, n)
		}
	}
}

// TestProtectedResourceForgetsANonceAfterA431: a nonce that got the
// request refused as too large is forgotten, so the next request goes
// out without it.
func TestProtectedResourceForgetsANonceAfterA431(t *testing.T) {
	ctx := context.Background()
	var (
		mu     sync.Mutex
		nonces []string
	)
	rs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := nonceClaim(t, r)
		mu.Lock()
		nonces = append(nonces, n)
		mu.Unlock()
		if n != "" {
			w.WriteHeader(http.StatusRequestHeaderFieldsTooLarge)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(rs.Close)
	c := newResourceTestClient(t, rs, nil)
	rc := c.ClientCredentialsResource(client.ClientCredentialsTokenResult{AccessToken: fapi.NewSecret("at")})
	rsURL, _ := url.Parse(rs.URL)
	rc.UseDPoPNonce(ctx, rsURL, "stale-nonce")
	var statuses []int
	for range 2 {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rs.URL+"/api", nil)
		if err != nil {
			t.Fatal(err)
		}
		res, err := rc.Do(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		statuses = append(statuses, res.StatusCode)
	}
	if statuses[0] != http.StatusRequestHeaderFieldsTooLarge || statuses[1] != http.StatusOK {
		t.Fatalf("statuses = %v, want [431 200]", statuses)
	}
	mu.Lock()
	defer mu.Unlock()
	if nonces[1] != "" {
		t.Errorf("second request presented %q", nonces[1])
	}
}

// nonceClaim is the nonce r's DPoP proof carries, "" for none.
func nonceClaim(t *testing.T, r *http.Request) string {
	t.Helper()
	n, _ := dpopProofClaims(t, r.Header.Get("DPoP"))["nonce"].(string)
	return n
}

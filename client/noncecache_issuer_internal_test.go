package client

import (
	"testing"

	fapi "github.com/idfoundry/fapigo"
)

// TestDPoPNonceScopeNamesTheIssuer: one DPoPNonceCache shared by clients
// for two issuers keeps each issuer's authorization server nonce apart.
func TestDPoPNonceScopeNamesTheIssuer(t *testing.T) {
	cache := NewInMemoryDPoPNonceCache()
	clientFor := func(issuer string) *Client {
		iss, err := fapi.ParseIssuerURL(issuer)
		if err != nil {
			t.Fatal(err)
		}
		return &Client{cfg: Config{Issuer: iss}, deps: Dependencies{DPoPNonceCache: cache}}
	}
	a, b := clientFor("https://a.example.com"), clientFor("https://b.example.com")
	a.cacheDPoPNonce(t.Context(), a.asNonceScope(), "nonce-from-a")
	if got := b.cachedDPoPNonce(t.Context(), b.asNonceScope()); got != "" {
		t.Errorf("issuer b's client got nonce %q from issuer a's server", got)
	}
	if got := a.cachedDPoPNonce(t.Context(), a.asNonceScope()); got != "nonce-from-a" {
		t.Errorf("issuer a's client got %q, want its own nonce", got)
	}
}

package keys_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/keys"
)

func p256JWKJSON(t *testing.T, pub *ecdsa.PublicKey, kid, alg string) string {
	t.Helper()
	size := 32
	x := base64.RawURLEncoding.EncodeToString(pub.X.FillBytes(make([]byte, size)))
	y := base64.RawURLEncoding.EncodeToString(pub.Y.FillBytes(make([]byte, size)))
	algField := ""
	if alg != "" {
		algField = fmt.Sprintf(`,"alg":%q`, alg)
	}
	return fmt.Sprintf(`{"kty":"EC","crv":"P-256","x":%q,"y":%q,"kid":%q,"use":"sig"%s}`, x, y, kid, algField)
}

func newTestFetcher(t *testing.T) *fapihttp.Client {
	t.Helper()
	c, err := fapihttp.New(http.DefaultClient, fapihttp.Config{
		MaxResponseBytes: 1 << 16,
		RequestTimeout:   5 * time.Second,
		MaxRedirects:     1,
	})
	if err != nil {
		t.Fatalf("fapihttp.New: %v", err)
	}
	return c
}

func TestJWKSIssuerKeySourceResolvesKeyByAlgorithm(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"keys":[%s]}`, p256JWKJSON(t, &priv.PublicKey, "kid-1", "ES256"))
	}))
	defer ts.Close()

	jwksURI, err := fapi.ParseEndpointURL(ts.URL + "/jwks")
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	src, err := keys.NewJWKSIssuerKeySource(newTestFetcherTLS(t, ts), jwksURI, time.Minute)
	if err != nil {
		t.Fatalf("NewJWKSIssuerKeySource: %v", err)
	}

	set, err := src.ResolveIssuerKeys(context.Background(), keys.IssuerKeyRequest{
		Issuer: "https://as.example.com", Purpose: keys.AccessTokenVerification, Algorithm: fapi.ES256,
	})
	if err != nil {
		t.Fatalf("ResolveIssuerKeys: %v", err)
	}
	if len(set.Keys) != 1 || set.Keys[0].KeyID != "kid-1" {
		t.Fatalf("Keys = %+v, want one key with kid-1", set.Keys)
	}
}

func newTestFetcherTLS(t *testing.T, ts *httptest.Server) *fapihttp.Client {
	t.Helper()
	c, err := fapihttp.New(ts.Client(), fapihttp.Config{
		MaxResponseBytes: 1 << 16,
		RequestTimeout:   5 * time.Second,
		MaxRedirects:     1,
		// ts is a local httptest server on loopback; fapihttp's SSRF
		// pre-check blocks loopback by default, so tests hitting it
		// need to opt in, the same as a real deployment would.
		AllowLoopbackHTTP: true,
	})
	if err != nil {
		t.Fatalf("fapihttp.New: %v", err)
	}
	return c
}

func TestJWKSIssuerKeySourceCachesWithinTTL(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	var fetches int32
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&fetches, 1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"keys":[%s]}`, p256JWKJSON(t, &priv.PublicKey, "kid-1", "ES256"))
	}))
	defer ts.Close()

	jwksURI, err := fapi.ParseEndpointURL(ts.URL + "/jwks")
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	src, err := keys.NewJWKSIssuerKeySource(newTestFetcherTLS(t, ts), jwksURI, time.Minute)
	if err != nil {
		t.Fatalf("NewJWKSIssuerKeySource: %v", err)
	}

	req := keys.IssuerKeyRequest{Issuer: "https://as.example.com", Purpose: keys.AccessTokenVerification, Algorithm: fapi.ES256}
	for i := 0; i < 3; i++ {
		if _, err := src.ResolveIssuerKeys(context.Background(), req); err != nil {
			t.Fatalf("ResolveIssuerKeys[%d]: %v", i, err)
		}
	}
	if got := atomic.LoadInt32(&fetches); got != 1 {
		t.Fatalf("fetches = %d, want 1 (cached)", got)
	}
}

func TestJWKSIssuerKeySourceRefreshesOnUnknownKeyID(t *testing.T) {
	oldKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	var rotated atomic.Bool
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if rotated.Load() {
			fmt.Fprintf(w, `{"keys":[%s]}`, p256JWKJSON(t, &newKey.PublicKey, "kid-new", "ES256"))
		} else {
			fmt.Fprintf(w, `{"keys":[%s]}`, p256JWKJSON(t, &oldKey.PublicKey, "kid-old", "ES256"))
		}
	}))
	defer ts.Close()

	jwksURI, err := fapi.ParseEndpointURL(ts.URL + "/jwks")
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	// Long TTL: without stale-key-triggered refresh, the second lookup
	// would never see the rotated key within this test's lifetime. A
	// minimal WithMinRefreshInterval keeps H-1's rate limit from
	// suppressing that second forced refresh — this test's two lookups
	// are sequential real calls (each doing a real fetch), so any
	// interval shorter than that gap still lets the second one through.
	src, err := keys.NewJWKSIssuerKeySource(newTestFetcherTLS(t, ts), jwksURI, time.Hour, keys.WithMinRefreshInterval(time.Nanosecond))
	if err != nil {
		t.Fatalf("NewJWKSIssuerKeySource: %v", err)
	}

	if _, err := src.ResolveIssuerKeys(context.Background(), keys.IssuerKeyRequest{
		Issuer: "https://as.example.com", Purpose: keys.AccessTokenVerification, Algorithm: fapi.ES256, KeyID: "kid-old",
	}); err != nil {
		t.Fatalf("ResolveIssuerKeys(kid-old): %v", err)
	}

	rotated.Store(true)
	set, err := src.ResolveIssuerKeys(context.Background(), keys.IssuerKeyRequest{
		Issuer: "https://as.example.com", Purpose: keys.AccessTokenVerification, Algorithm: fapi.ES256, KeyID: "kid-new",
	})
	if err != nil {
		t.Fatalf("ResolveIssuerKeys(kid-new): %v", err)
	}
	if len(set.Keys) != 1 || set.Keys[0].KeyID != "kid-new" {
		t.Fatalf("Keys = %+v, want one key with kid-new (stale-key refresh should have found it)", set.Keys)
	}
}

func TestJWKSIssuerKeySourceSkipsUnsupportedAlgorithmEntries(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// An RS256 entry with garbage RSA fields (this module doesn't
		// implement RS256 at all, so it must be skipped without even
		// trying to decode n/e) alongside one good ES256 entry.
		fmt.Fprintf(w, `{"keys":[{"kty":"RSA","alg":"RS256","kid":"kid-rsa","n":"not-valid-base64!!","e":"AQAB"},%s]}`,
			p256JWKJSON(t, &priv.PublicKey, "kid-es256", "ES256"))
	}))
	defer ts.Close()

	jwksURI, err := fapi.ParseEndpointURL(ts.URL + "/jwks")
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	src, err := keys.NewJWKSIssuerKeySource(newTestFetcherTLS(t, ts), jwksURI, time.Minute)
	if err != nil {
		t.Fatalf("NewJWKSIssuerKeySource: %v", err)
	}

	set, err := src.ResolveIssuerKeys(context.Background(), keys.IssuerKeyRequest{
		Issuer: "https://as.example.com", Purpose: keys.AccessTokenVerification, Algorithm: fapi.ES256,
	})
	if err != nil {
		t.Fatalf("ResolveIssuerKeys: %v", err)
	}
	if len(set.Keys) != 1 || set.Keys[0].KeyID != "kid-es256" {
		t.Fatalf("Keys = %+v, want exactly the ES256 key", set.Keys)
	}
}

func TestJWKSIssuerKeySourceFailsOnEmptyKeySet(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"keys":[]}`))
	}))
	defer ts.Close()

	jwksURI, err := fapi.ParseEndpointURL(ts.URL + "/jwks")
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	src, err := keys.NewJWKSIssuerKeySource(newTestFetcherTLS(t, ts), jwksURI, time.Minute)
	if err != nil {
		t.Fatalf("NewJWKSIssuerKeySource: %v", err)
	}
	if _, err := src.ResolveIssuerKeys(context.Background(), keys.IssuerKeyRequest{
		Issuer: "https://as.example.com", Algorithm: fapi.ES256,
	}); err == nil {
		t.Fatalf("ResolveIssuerKeys(empty key set) = nil error, want error")
	}
}

func TestNewJWKSIssuerKeySourceRejectsInvalidArgs(t *testing.T) {
	validURI, err := fapi.ParseEndpointURL("https://as.example.com/jwks")
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	if _, err := keys.NewJWKSIssuerKeySource(nil, validURI, time.Minute); err == nil {
		t.Fatalf("NewJWKSIssuerKeySource(nil fetcher) = nil error, want error")
	}
	if _, err := keys.NewJWKSIssuerKeySource(newTestFetcher(t), fapi.URL{}, time.Minute); err == nil {
		t.Fatalf("NewJWKSIssuerKeySource(zero URI) = nil error, want error")
	}
	if _, err := keys.NewJWKSIssuerKeySource(newTestFetcher(t), validURI, 0); err == nil {
		t.Fatalf("NewJWKSIssuerKeySource(zero TTL) = nil error, want error")
	}
}

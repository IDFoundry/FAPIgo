package ephemeral

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/keys"
)

func TestKeyManagerSignAndVerifyRoundTrip(t *testing.T) {
	m, err := NewKeyManager(map[keys.SigningPurpose]fapi.SignatureAlgorithm{
		keys.AccessTokenSigning: fapi.ES256,
		keys.IDTokenSigning:     fapi.PS256,
	})
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}

	digest := sha256.Sum256([]byte("hello"))
	sig, err := m.Sign(context.Background(), keys.SigningRequest{
		Purpose: keys.AccessTokenSigning, Algorithm: fapi.ES256, Digest: digest[:],
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if sig.KeyID == "" {
		t.Fatal("Sign returned an empty KeyID")
	}

	info, err := m.PublicKey(context.Background(), keys.AccessTokenSigning, fapi.ES256)
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if info.KeyID != sig.KeyID {
		t.Fatalf("PublicKey KeyID = %q, want %q (must match Sign's)", info.KeyID, sig.KeyID)
	}
	pub, ok := info.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("PublicKey type = %T, want *ecdsa.PublicKey", info.PublicKey)
	}
	if !ecdsa.VerifyASN1(pub, digest[:], sig.Value) {
		t.Fatal("signature does not verify against PublicKey's own reported key")
	}
}

// TestKeyManagerSignAndVerifyRoundTripEdDSA mirrors
// TestKeyManagerSignAndVerifyRoundTrip for EdDSA, whose SigningRequest
// carries SigningInput (the raw message) rather than Digest — see
// keys.SigningRequest's own doc comment for why the two algorithm
// families can't share a field.
func TestKeyManagerSignAndVerifyRoundTripEdDSA(t *testing.T) {
	m, err := NewKeyManager(map[keys.SigningPurpose]fapi.SignatureAlgorithm{
		keys.RequestObjectSigning: fapi.EdDSA,
	})
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}

	message := []byte("hello")
	sig, err := m.Sign(context.Background(), keys.SigningRequest{
		Purpose: keys.RequestObjectSigning, Algorithm: fapi.EdDSA, SigningInput: message,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if sig.KeyID == "" {
		t.Fatal("Sign returned an empty KeyID")
	}

	info, err := m.PublicKey(context.Background(), keys.RequestObjectSigning, fapi.EdDSA)
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if info.KeyID != sig.KeyID {
		t.Fatalf("PublicKey KeyID = %q, want %q (must match Sign's)", info.KeyID, sig.KeyID)
	}
	pub, ok := info.PublicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("PublicKey type = %T, want ed25519.PublicKey", info.PublicKey)
	}
	if !ed25519.Verify(pub, message, sig.Value) {
		t.Fatal("signature does not verify against PublicKey's own reported key")
	}
}

// TestKeyManagerEdDSAIgnoresDigestField confirms Sign actually uses
// SigningInput for EdDSA, not whatever might be left in Digest — a
// caller that populated both (or the wrong one) should get a signature
// over the message it meant to sign, not a silent fallback.
func TestKeyManagerEdDSAIgnoresDigestField(t *testing.T) {
	m, err := NewKeyManager(map[keys.SigningPurpose]fapi.SignatureAlgorithm{
		keys.RequestObjectSigning: fapi.EdDSA,
	})
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}

	message := []byte("the real message")
	sig, err := m.Sign(context.Background(), keys.SigningRequest{
		Purpose: keys.RequestObjectSigning, Algorithm: fapi.EdDSA,
		SigningInput: message, Digest: []byte("stale digest that must be ignored"),
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	info, err := m.PublicKey(context.Background(), keys.RequestObjectSigning, fapi.EdDSA)
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	pub := info.PublicKey.(ed25519.PublicKey)
	if !ed25519.Verify(pub, message, sig.Value) {
		t.Fatal("signature does not verify against SigningInput — Digest was used instead")
	}
}

func TestKeyManagerRejectsUnsupportedAlgorithm(t *testing.T) {
	if _, err := NewKeyManager(map[keys.SigningPurpose]fapi.SignatureAlgorithm{
		keys.AccessTokenSigning: fapi.SignatureAlgorithm(0),
	}); err == nil {
		t.Fatal("NewKeyManager(unsupported algorithm) = nil error, want error")
	}
}

func TestKeyManagerRejectsUnknownPurpose(t *testing.T) {
	m, err := NewKeyManager(map[keys.SigningPurpose]fapi.SignatureAlgorithm{keys.AccessTokenSigning: fapi.ES256})
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}
	if _, err := m.Sign(context.Background(), keys.SigningRequest{Purpose: keys.IDTokenSigning, Digest: []byte("x")}); err == nil {
		t.Fatal("Sign(unconfigured purpose) = nil error, want error")
	}
}

func p256JWKJSON(t *testing.T, pub *ecdsa.PublicKey, kid, alg string) string {
	t.Helper()
	size := 32
	x := base64.RawURLEncoding.EncodeToString(pub.X.FillBytes(make([]byte, size)))
	y := base64.RawURLEncoding.EncodeToString(pub.Y.FillBytes(make([]byte, size)))
	return fmt.Sprintf(`{"kty":"EC","crv":"P-256","x":%q,"y":%q,"kid":%q,"use":"sig","alg":%q}`, x, y, kid, alg)
}

func TestClientKeySourceStaticJWKS(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jwks := []byte(fmt.Sprintf(`{"keys":[%s]}`, p256JWKJSON(t, &priv.PublicKey, "kid-1", "ES256")))

	src, err := NewClientKeySource(nil, []ClientKeySpec{{ClientID: "client-1", JWKS: jwks}})
	if err != nil {
		t.Fatalf("NewClientKeySource: %v", err)
	}

	set, err := src.ResolveVerificationKeys(context.Background(), keys.ClientKeyRequest{
		ClientID: "client-1", Algorithm: fapi.ES256,
	})
	if err != nil {
		t.Fatalf("ResolveVerificationKeys: %v", err)
	}
	if len(set.Keys) != 1 || set.Keys[0].KeyID != "kid-1" {
		t.Fatalf("Keys = %+v, want one key with kid-1", set.Keys)
	}
}

func TestClientKeySourceFetchedJWKS(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"keys":[%s]}`, p256JWKJSON(t, &priv.PublicKey, "kid-2", "ES256"))
	}))
	defer ts.Close()

	fetcher, err := fapihttp.New(ts.Client(), fapihttp.Config{
		MaxResponseBytes: 1 << 16,
		RequestTimeout:   5 * time.Second,
		MaxRedirects:     1,
		// ts is a local httptest server on loopback; opt in to
		// fapihttp's SSRF pre-check allowing it, same as a real
		// deployment pointing at a loopback issuer would.
		AllowLoopbackHTTP: true,
	})
	if err != nil {
		t.Fatalf("fapihttp.New: %v", err)
	}

	src, err := NewClientKeySource(fetcher, []ClientKeySpec{{ClientID: "client-1", JWKSURI: ts.URL + "/jwks"}}, WithCacheTTL(time.Minute))
	if err != nil {
		t.Fatalf("NewClientKeySource: %v", err)
	}

	set, err := src.ResolveVerificationKeys(context.Background(), keys.ClientKeyRequest{
		ClientID: "client-1", Algorithm: fapi.ES256,
	})
	if err != nil {
		t.Fatalf("ResolveVerificationKeys: %v", err)
	}
	if len(set.Keys) != 1 || set.Keys[0].KeyID != "kid-2" {
		t.Fatalf("Keys = %+v, want one key with kid-2", set.Keys)
	}
}

// TestClientKeySourceCachesWithinTTL covers currentFetchedKeys' fresh-
// cache-hit path, which had no direct test: TestClientKeySourceFetchedJWKS
// only ever exercises the cold-cache first fetch.
func TestClientKeySourceCachesWithinTTL(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	var fetches int
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches++
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"keys":[%s]}`, p256JWKJSON(t, &priv.PublicKey, "kid-1", "ES256"))
	}))
	defer ts.Close()

	fetcher, err := fapihttp.New(ts.Client(), fapihttp.Config{
		MaxResponseBytes: 1 << 16,
		RequestTimeout:   5 * time.Second,
		MaxRedirects:     1,
		// ts is a local httptest server on loopback; opt in to
		// fapihttp's SSRF pre-check allowing it, same as a real
		// deployment pointing at a loopback issuer would.
		AllowLoopbackHTTP: true,
	})
	if err != nil {
		t.Fatalf("fapihttp.New: %v", err)
	}

	src, err := NewClientKeySource(fetcher, []ClientKeySpec{{ClientID: "client-1", JWKSURI: ts.URL + "/jwks"}}, WithCacheTTL(time.Minute))
	if err != nil {
		t.Fatalf("NewClientKeySource: %v", err)
	}

	for i := 0; i < 2; i++ {
		if _, err := src.ResolveVerificationKeys(context.Background(), keys.ClientKeyRequest{
			ClientID: "client-1", Algorithm: fapi.ES256, KeyID: "kid-1",
		}); err != nil {
			t.Fatalf("ResolveVerificationKeys[%d]: %v", i, err)
		}
	}
	if fetches != 1 {
		t.Fatalf("fetches = %d, want 1 (second resolve should be served from cache)", fetches)
	}
}

// TestClientKeySourceRefetchesOnUnknownKeyIDEvenWhenCacheFresh covers
// currentFetchedKeys' stale-key handling: a client that has rotated
// keys since the last fetch must not be stuck with a cached set that
// never contains the newly requested kid until the TTL expires.
func TestClientKeySourceRefetchesOnUnknownKeyIDEvenWhenCacheFresh(t *testing.T) {
	priv1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	priv2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	var fetches int
	var mu sync.Mutex
	rotated := false
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		fetches++
		w.Header().Set("Content-Type", "application/json")
		if rotated {
			fmt.Fprintf(w, `{"keys":[%s]}`, p256JWKJSON(t, &priv2.PublicKey, "kid-2", "ES256"))
		} else {
			fmt.Fprintf(w, `{"keys":[%s]}`, p256JWKJSON(t, &priv1.PublicKey, "kid-1", "ES256"))
		}
	}))
	defer ts.Close()

	fetcher, err := fapihttp.New(ts.Client(), fapihttp.Config{
		MaxResponseBytes: 1 << 16,
		RequestTimeout:   5 * time.Second,
		MaxRedirects:     1,
		// ts is a local httptest server on loopback; opt in to
		// fapihttp's SSRF pre-check allowing it, same as a real
		// deployment pointing at a loopback issuer would.
		AllowLoopbackHTTP: true,
	})
	if err != nil {
		t.Fatalf("fapihttp.New: %v", err)
	}

	src, err := NewClientKeySource(fetcher, []ClientKeySpec{{ClientID: "client-1", JWKSURI: ts.URL + "/jwks"}}, WithCacheTTL(time.Minute))
	if err != nil {
		t.Fatalf("NewClientKeySource: %v", err)
	}

	if _, err := src.ResolveVerificationKeys(context.Background(), keys.ClientKeyRequest{
		ClientID: "client-1", Algorithm: fapi.ES256, KeyID: "kid-1",
	}); err != nil {
		t.Fatalf("ResolveVerificationKeys(kid-1): %v", err)
	}

	mu.Lock()
	rotated = true
	mu.Unlock()

	set, err := src.ResolveVerificationKeys(context.Background(), keys.ClientKeyRequest{
		ClientID: "client-1", Algorithm: fapi.ES256, KeyID: "kid-2",
	})
	if err != nil {
		t.Fatalf("ResolveVerificationKeys(kid-2): %v", err)
	}
	if len(set.Keys) != 1 || set.Keys[0].KeyID != "kid-2" {
		t.Fatalf("Keys = %+v, want one key with kid-2 (rotation should force a refetch)", set.Keys)
	}
	if fetches != 2 {
		t.Fatalf("fetches = %d, want 2 (requesting an unknown kid must force a refetch even within TTL)", fetches)
	}
}

func TestClientKeySourceRejectsUnknownClient(t *testing.T) {
	src, err := NewClientKeySource(nil, nil)
	if err != nil {
		t.Fatalf("NewClientKeySource: %v", err)
	}
	if _, err := src.ResolveVerificationKeys(context.Background(), keys.ClientKeyRequest{ClientID: "client-1", Algorithm: fapi.ES256}); err == nil {
		t.Fatal("ResolveVerificationKeys(unknown client) = nil error, want error")
	}
}

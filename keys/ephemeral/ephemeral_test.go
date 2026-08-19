package ephemeral

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
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

func TestClientKeySourceRejectsUnknownClient(t *testing.T) {
	src, err := NewClientKeySource(nil, nil)
	if err != nil {
		t.Fatalf("NewClientKeySource: %v", err)
	}
	if _, err := src.ResolveVerificationKeys(context.Background(), keys.ClientKeyRequest{ClientID: "client-1", Algorithm: fapi.ES256}); err == nil {
		t.Fatal("ResolveVerificationKeys(unknown client) = nil error, want error")
	}
}

package ephemeral

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/keys"
)

// p256JWKWithoutKeyID is pub as a JWK with no kid member.
func p256JWKWithoutKeyID(pub *ecdsa.PublicKey) string {
	x := base64.RawURLEncoding.EncodeToString(pub.X.FillBytes(make([]byte, 32)))
	y := base64.RawURLEncoding.EncodeToString(pub.Y.FillBytes(make([]byte, 32)))
	return fmt.Sprintf(`{"kty":"EC","crv":"P-256","x":%q,"y":%q,"use":"sig","alg":"ES256"}`, x, y)
}

// rsaJWKWithoutKeyID is pub as a JWK with no kid and no alg member, so
// its algorithm is taken to be PS256.
func rsaJWKWithoutKeyID(pub *rsa.PublicKey) string {
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	return fmt.Sprintf(`{"kty":"RSA","n":%q,"e":%q}`, n, e)
}

// ed25519JWKWithoutKeyID is pub as a JWK with no kid and no alg member,
// so its algorithm is taken to be EdDSA.
func ed25519JWKWithoutKeyID(pub ed25519.PublicKey) string {
	return fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":%q}`, base64.RawURLEncoding.EncodeToString(pub))
}

// generateP256 is a fresh P-256 key.
func generateP256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

// derivedKeyID is the kid keys.NewKeyManagerFromSigners derives for
// key, signing with alg, when its SignerSpec names none: key's RFC 7638
// thumbprint.
func derivedKeyID(t *testing.T, key crypto.Signer, alg fapi.SignatureAlgorithm) string {
	t.Helper()
	km, err := keys.NewKeyManagerFromSigners([]keys.SignerSpec{{Purpose: keys.ClientAuthentication, Algorithm: alg, Signer: key}})
	if err != nil {
		t.Fatalf("NewKeyManagerFromSigners: %v", err)
	}
	info, err := km.PublicKey(context.Background(), keys.ClientAuthentication, alg)
	if err != nil || info.KeyID == "" {
		t.Fatalf("PublicKey = %+v, %v; want a derived kid", info, err)
	}
	return info.KeyID
}

// TestClientKeySourceMatchesThumbprintOfKeyWithoutKeyID: a JWK Set
// entry with no kid answers to a request naming its RFC 7638
// thumbprint, the kid keys.NewKeyManagerFromSigners derives for it, as
// keys.VerificationKey.KeyID sets out for every client key source,
// whether it is a P-256, an RSA or an Ed25519 key. An entry with a kid
// answers to that kid alone, and neither answers to another client's
// key's thumbprint.
func TestClientKeySourceMatchesThumbprintOfKeyWithoutKeyID(t *testing.T) {
	kidless, named, other := generateP256(t), generateP256(t), generateP256(t)
	rsaKidless, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	edPub, edKidless, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	src, err := NewClientKeySource(nil, []ClientKeySpec{
		{ClientID: "client-1", JWKS: fmt.Appendf(nil, `{"keys":[%s,%s,%s,%s]}`,
			p256JWKWithoutKeyID(&kidless.PublicKey), p256JWKJSON(t, &named.PublicKey, "named", "ES256"),
			rsaJWKWithoutKeyID(&rsaKidless.PublicKey), ed25519JWKWithoutKeyID(edPub))},
		{ClientID: "client-2", JWKS: fmt.Appendf(nil, `{"keys":[%s]}`, p256JWKWithoutKeyID(&other.PublicKey))},
	})
	if err != nil {
		t.Fatalf("NewClientKeySource: %v", err)
	}
	for _, tc := range []struct {
		name string
		alg  fapi.SignatureAlgorithm
		kid  string
		want crypto.PublicKey // nil: no key
	}{
		{"the kid-less entry's thumbprint", fapi.ES256, derivedKeyID(t, kidless, fapi.ES256), &kidless.PublicKey},
		{"the kid-less RSA entry's thumbprint", fapi.PS256, derivedKeyID(t, rsaKidless, fapi.PS256), &rsaKidless.PublicKey},
		{"the kid-less Ed25519 entry's thumbprint", fapi.EdDSA, derivedKeyID(t, edKidless, fapi.EdDSA), edPub},
		{"the named entry's kid", fapi.ES256, "named", &named.PublicKey},
		{"the named entry's thumbprint", fapi.ES256, derivedKeyID(t, named, fapi.ES256), nil},
		{"another client's key's thumbprint", fapi.ES256, derivedKeyID(t, other, fapi.ES256), nil},
		{"an unrelated kid", fapi.ES256, "unrelated", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			set, err := src.ResolveVerificationKeys(context.Background(), keys.ClientKeyRequest{ClientID: "client-1", Algorithm: tc.alg, KeyID: tc.kid})
			if err != nil {
				t.Fatalf("ResolveVerificationKeys: %v", err)
			}
			requireResolvedKey(t, set, tc.want)
		})
	}
}

// TestClientKeySourceServesThumbprintKeyIDFromFreshCache: a fresh
// fetched set holding a kid-less key answers a request naming that
// key's thumbprint itself, rather than treating the kid as one rotated
// in since the fetch and fetching the set again.
func TestClientKeySourceServesThumbprintKeyIDFromFreshCache(t *testing.T) {
	key := generateP256(t)
	var fetches atomic.Int32
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"keys":[%s]}`, p256JWKWithoutKeyID(&key.PublicKey))
	}))
	defer ts.Close()
	fetcher, err := fapihttp.New(ts.Client(), fapihttp.Config{
		MaxResponseBytes: 1 << 16, RequestTimeout: 5 * time.Second, MaxRedirects: 1, AllowLoopbackHTTP: true,
	})
	if err != nil {
		t.Fatalf("fapihttp.New: %v", err)
	}
	src, err := NewClientKeySource(fetcher, []ClientKeySpec{{ClientID: "client-1", JWKSURI: ts.URL + "/jwks"}},
		WithCacheTTL(time.Minute), WithMinRefreshInterval(time.Second))
	if err != nil {
		t.Fatalf("NewClientKeySource: %v", err)
	}
	now := time.Now()
	src.now = func() time.Time { return now }
	kid := derivedKeyID(t, key, fapi.ES256)
	for i := range 3 {
		set, err := src.ResolveVerificationKeys(context.Background(), keys.ClientKeyRequest{ClientID: "client-1", Algorithm: fapi.ES256, KeyID: kid})
		if err != nil || len(set.Keys) != 1 {
			t.Fatalf("request %d: ResolveVerificationKeys = %d keys, %v; want the key", i, len(set.Keys), err)
		}
		// Past the minimum refresh interval, so a kid the set seemed
		// to lack would force a fetch.
		now = now.Add(2 * time.Second)
	}
	if n := fetches.Load(); n != 1 {
		t.Fatalf("%d fetches, want 1: the fresh set answers its own key's thumbprint", n)
	}
}

// requireResolvedKey fails t unless set holds want alone, or no key
// when want is nil.
func requireResolvedKey(t *testing.T, set keys.VerificationKeySet, want crypto.PublicKey) {
	t.Helper()
	if want == nil {
		if len(set.Keys) != 0 {
			t.Fatalf("ResolveVerificationKeys = %d keys, want none", len(set.Keys))
		}
		return
	}
	if len(set.Keys) != 1 || !want.(interface{ Equal(crypto.PublicKey) bool }).Equal(set.Keys[0].PublicKey) {
		t.Fatalf("ResolveVerificationKeys = %+v, want the one key", set.Keys)
	}
}

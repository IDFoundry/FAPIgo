package dpop

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/url"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
)

// FuzzVerifyDPoPProof exercises Verify against arbitrary DPoP proof
// strings — attacker-controlled per request, and self-signed (the
// verification key comes from the proof's own embedded "jwk" header,
// not an external source), so a malicious proof only has to convince
// this package, not impersonate a registered key. Method/URL/Now etc.
// are fixed to a realistic request so the fuzzer's mutations land on
// the one field that's actually untrusted. Exercises jose.ParseJWK's
// embedded-header path (unlike internal/jose.FuzzParseJWK's standalone
// JWK Set entries) plus parseClaims' htm/htu/ath/nonce/iat handling.
// Only checks for panics/hangs.
func FuzzVerifyDPoPProof(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate key: %v", err)
	}
	reqURL, err := url.Parse("https://as.example/token")
	if err != nil {
		f.Fatalf("parse url: %v", err)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	const accessToken = "fuzz-access-token"
	const nonce = "fuzz-nonce"

	minimal, err := CreateProof(ProofRequest{
		Signer: key, Algorithm: fapi.ES256, Method: "POST", URL: reqURL, Now: now,
	})
	if err != nil {
		f.Fatalf("CreateProof(minimal): %v", err)
	}
	withExtras, err := CreateProof(ProofRequest{
		Signer: key, Algorithm: fapi.ES256, Method: "POST", URL: reqURL, Now: now,
		AccessToken: accessToken, Nonce: nonce,
	})
	if err != nil {
		f.Fatalf("CreateProof(with extras): %v", err)
	}

	noJWK, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256, Type: jwtType}, []byte(`{"jti":"x","htm":"POST","htu":"https://as.example/token","iat":1735689600}`))
	if err != nil {
		f.Fatalf("sign no-jwk token: %v", err)
	}
	wrongType, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256, Type: "not-dpop+jwt"}, []byte(`{}`))
	if err != nil {
		f.Fatalf("sign wrong-type token: %v", err)
	}

	f.Add(minimal)
	f.Add(withExtras)
	f.Add(noJWK)
	f.Add(wrongType)
	f.Add("")
	f.Add(".")
	f.Add("a.b.c")

	f.Fuzz(func(t *testing.T, proof string) {
		_, _ = Verify(context.Background(), VerifyRequest{
			Proof: proof, Method: "POST", URL: reqURL,
			AccessToken: accessToken, RequiredNonce: nonce,
			Now: now, MaxProofAge: time.Hour,
		})
	})
}

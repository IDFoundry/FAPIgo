package clientattestation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
)

// FuzzParsePoP exercises ParsePoP against arbitrary strings — a Client
// Attestation PoP JWT is client-supplied and, unlike the Client
// Attestation JWT it accompanies, meant to be single-use per request,
// parsed before any signature is checked. Only checks for
// panics/hangs.
func FuzzParsePoP(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate key: %v", err)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	withoutChallenge, err := CreatePoP(PoPCreateRequest{
		Signer: key, Algorithm: fapi.ES256,
		ClientID: "https://client.example", Audience: "https://as.example",
		Now: now,
	})
	if err != nil {
		f.Fatalf("CreatePoP(without challenge): %v", err)
	}
	withChallenge, err := CreatePoP(PoPCreateRequest{
		Signer: key, Algorithm: fapi.ES256,
		ClientID: "https://client.example", Audience: "https://as.example",
		Now: now, Challenge: "fuzz-challenge",
	})
	if err != nil {
		f.Fatalf("CreatePoP(with challenge): %v", err)
	}

	f.Add(withoutChallenge)
	f.Add(withChallenge)
	// draft-12's shape — no iss — with aud as a string and as an array,
	// and with exp, which neither draft defines for a PoP.
	sign := func(payload string) string {
		compact, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256, Type: PoPTypHeader}, []byte(payload))
		if err != nil {
			f.Fatalf("sign: %v", err)
		}
		return compact
	}
	f.Add(sign(`{"aud":"https://as.example","jti":"j","iat":1767225600}`))
	f.Add(sign(`{"aud":["https://as.example"],"jti":"j","iat":1767225600,"exp":1767225660}`))
	f.Add(sign(`{"aud":["https://as.example","https://other.example"],"jti":"j","iat":1767225600}`))
	f.Add("")
	f.Add(".")
	f.Add("a.b.c")

	f.Fuzz(func(t *testing.T, pop string) {
		_, _ = ParsePoP(pop)
	})
}

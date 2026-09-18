package federation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
)

// FuzzParseHistoricalKeysResponse exercises ParseHistoricalKeysResponse
// against arbitrary strings. A Federation Historical Keys response
// (OpenID Federation 1.0 §8.7) is fetched from an entity's own
// federation_historical_keys_endpoint — external, parsed before any
// signature is checked. Exercises parseHistoricalKeysClaims' own "keys"
// array handling (each entry's iat/exp/nbf/revoked members, on top of
// the JWK material jose.FuzzParseJWKSet already covers via a synthetic
// set) — a shape no other fuzz target in this repo reaches. Only checks
// for panics/hangs.
func FuzzParseHistoricalKeysResponse(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate key: %v", err)
	}
	historicalKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate historical key: %v", err)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	expiredOnly, err := CreateHistoricalKeysResponse(CreateHistoricalKeysResponseParams{
		Signer: key, Algorithm: fapi.ES256, KeyID: "fuzz-kid",
		Issuer: "https://entity.example", Now: now,
		Keys: []HistoricalKeyParams{
			{KeyID: "old-kid", Algorithm: fapi.ES256, PublicKey: &historicalKey.PublicKey, ExpiresAt: now.Add(-time.Hour)},
		},
	})
	if err != nil {
		f.Fatalf("CreateHistoricalKeysResponse(expired only): %v", err)
	}

	revoked, err := CreateHistoricalKeysResponse(CreateHistoricalKeysResponseParams{
		Signer: key, Algorithm: fapi.ES256, KeyID: "fuzz-kid",
		Issuer: "https://entity.example", Now: now,
		Keys: []HistoricalKeyParams{
			{
				KeyID: "old-kid", Algorithm: fapi.ES256, PublicKey: &historicalKey.PublicKey,
				IssuedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour), NotBefore: now.Add(-2 * time.Hour),
				Revoked: &KeyRevocation{RevokedAt: now.Add(-90 * time.Minute), Reason: KeyRevocationReasonCompromised},
			},
		},
	})
	if err != nil {
		f.Fatalf("CreateHistoricalKeysResponse(revoked): %v", err)
	}

	wrongType, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256, Type: "not-jwk-set+jwt"}, []byte(`{}`))
	if err != nil {
		f.Fatalf("sign wrong-type token: %v", err)
	}

	f.Add(expiredOnly)
	f.Add(revoked)
	f.Add(wrongType)
	f.Add("")
	f.Add(".")
	f.Add("a.b.c")

	f.Fuzz(func(t *testing.T, token string) {
		_, _ = ParseHistoricalKeysResponse(token)
	})
}

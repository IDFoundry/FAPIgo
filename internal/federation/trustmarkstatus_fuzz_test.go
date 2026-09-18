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

// FuzzParseTrustMarkStatusResponse exercises
// ParseTrustMarkStatusResponse against arbitrary strings. A Trust Mark
// Status Response (OpenID Federation 1.0 §8) is fetched from a Trust
// Mark Issuer's own federation_trust_mark_status_endpoint — external,
// parsed before any signature is checked. Exercises
// parseTrustMarkStatusResponseClaims' own "status" enum handling, a
// shape no other fuzz target reaches. Only checks for panics/hangs.
func FuzzParseTrustMarkStatusResponse(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate key: %v", err)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	active, err := CreateTrustMarkStatusResponse(CreateTrustMarkStatusResponseParams{
		Signer: key, Algorithm: fapi.ES256, KeyID: "fuzz-kid",
		Issuer: "https://trust-mark-issuer.example", TrustMark: "not-a-real-jwt",
		Status: TrustMarkStatusActive, Now: now,
	})
	if err != nil {
		f.Fatalf("CreateTrustMarkStatusResponse(active): %v", err)
	}

	revoked, err := CreateTrustMarkStatusResponse(CreateTrustMarkStatusResponseParams{
		Signer: key, Algorithm: fapi.ES256, KeyID: "fuzz-kid",
		Issuer: "https://trust-mark-issuer.example", TrustMark: "not-a-real-jwt",
		Status: TrustMarkStatusRevoked, Now: now,
	})
	if err != nil {
		f.Fatalf("CreateTrustMarkStatusResponse(revoked): %v", err)
	}

	wrongType, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256, Type: "not-trust-mark-status-response+jwt"}, []byte(`{}`))
	if err != nil {
		f.Fatalf("sign wrong-type token: %v", err)
	}

	f.Add(active)
	f.Add(revoked)
	f.Add(wrongType)
	f.Add("")
	f.Add(".")
	f.Add("a.b.c")

	f.Fuzz(func(t *testing.T, token string) {
		_, _ = ParseTrustMarkStatusResponse(token)
	})
}

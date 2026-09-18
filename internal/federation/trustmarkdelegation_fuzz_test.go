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

// FuzzParseTrustMarkDelegation exercises ParseTrustMarkDelegation
// against arbitrary strings. A Trust Mark Delegation JWT arrives inside
// a Trust Mark's own unverified "delegation" claim (see
// FuzzParseTrustMark) — external, attacker-controlled input by the same
// reasoning as every other Parse* target in this package. Exercises
// parseTrustMarkDelegationClaims' own handling, including the optional
// "exp" claim (a delegation's own exp may legitimately be absent, the
// same shape as a Trust Mark's own). Only checks for panics/hangs.
func FuzzParseTrustMarkDelegation(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate key: %v", err)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	withExpiry, err := CreateTrustMarkDelegation(CreateTrustMarkDelegationParams{
		Signer: key, Algorithm: fapi.ES256, KeyID: "fuzz-kid",
		Issuer: "https://owner.example", Subject: "https://delegate.example",
		TrustMarkType: "https://trust-mark.example",
		Now:           now, Lifetime: time.Hour,
	})
	if err != nil {
		f.Fatalf("CreateTrustMarkDelegation(with expiry): %v", err)
	}

	noExpiry, err := CreateTrustMarkDelegation(CreateTrustMarkDelegationParams{
		Signer: key, Algorithm: fapi.ES256, KeyID: "fuzz-kid",
		Issuer: "https://owner.example", Subject: "https://delegate.example",
		TrustMarkType: "https://trust-mark.example",
		Now:           now, // Lifetime left zero: "exp" omitted entirely.
	})
	if err != nil {
		f.Fatalf("CreateTrustMarkDelegation(no expiry): %v", err)
	}

	wrongType, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256, Type: "not-trust-mark-delegation+jwt"}, []byte(`{}`))
	if err != nil {
		f.Fatalf("sign wrong-type token: %v", err)
	}

	f.Add(withExpiry)
	f.Add(noExpiry)
	f.Add(wrongType)
	f.Add("")
	f.Add(".")
	f.Add("a.b.c")

	f.Fuzz(func(t *testing.T, token string) {
		_, _ = ParseTrustMarkDelegation(token)
	})
}

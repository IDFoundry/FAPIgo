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

// FuzzParseTrustMark exercises ParseTrustMark against arbitrary
// strings. A Trust Mark JWT is fetched (or embedded in an Entity
// Configuration's own "trust_marks" claim) from a party this package's
// own doc.go describes as needing an independently-resolved Trust Chain
// before any of it can be trusted — Parse itself runs before that,
// against fully untrusted bytes. Exercises parseTrustMarkClaims'
// federation-specific handling (in particular the optional "exp" claim
// — unlike an Entity Statement's, a Trust Mark's own exp may be
// legitimately absent) beyond what FuzzParseEntityStatement's shared
// jose.ParseCompact path already covers. Only checks for panics/hangs.
func FuzzParseTrustMark(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate key: %v", err)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	withExpiry, err := CreateTrustMark(CreateTrustMarkParams{
		Signer: key, Algorithm: fapi.ES256, KeyID: "fuzz-kid",
		Issuer: "https://trust-mark-issuer.example", Subject: "https://entity.example",
		TrustMarkType: "https://trust-mark.example",
		Now:           now, Lifetime: time.Hour,
	})
	if err != nil {
		f.Fatalf("CreateTrustMark(with expiry): %v", err)
	}

	noExpiry, err := CreateTrustMark(CreateTrustMarkParams{
		Signer: key, Algorithm: fapi.ES256, KeyID: "fuzz-kid",
		Issuer: "https://trust-mark-issuer.example", Subject: "https://entity.example",
		TrustMarkType: "https://trust-mark.example",
		Now:           now, // Lifetime left zero: "exp" omitted entirely.
	})
	if err != nil {
		f.Fatalf("CreateTrustMark(no expiry): %v", err)
	}

	withDelegation, err := CreateTrustMark(CreateTrustMarkParams{
		Signer: key, Algorithm: fapi.ES256, KeyID: "fuzz-kid",
		Issuer: "https://delegate.example", Subject: "https://entity.example",
		TrustMarkType: "https://trust-mark.example",
		Now:           now, Lifetime: time.Hour,
		Delegation: "not-a-real-jwt",
	})
	if err != nil {
		f.Fatalf("CreateTrustMark(with delegation): %v", err)
	}

	wrongType, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256, Type: "not-trust-mark+jwt"}, []byte(`{}`))
	if err != nil {
		f.Fatalf("sign wrong-type token: %v", err)
	}

	f.Add(withExpiry)
	f.Add(noExpiry)
	f.Add(withDelegation)
	f.Add(wrongType)
	f.Add("")
	f.Add(".")
	f.Add("a.b.c")

	f.Fuzz(func(t *testing.T, token string) {
		_, _ = ParseTrustMark(token)
	})
}

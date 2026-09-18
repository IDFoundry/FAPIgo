package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
)

// FuzzParseAccessToken exercises ParseAccessToken against arbitrary
// strings — a bearer or sender-constrained access token presented in a
// resource server's Authorization header, the single most directly
// attacker-controlled input in the whole protocol: this package's own
// AccessToken doc comment stresses that "nothing... including its
// scope or confirmation claim, should influence an authorization
// decision until Validate succeeds." Exercises parseAccessTokenClaims'
// own handling (the RFC 9068 audience-as-array-or-string shape, and
// the DPoP/mTLS-exclusive cnf claim) beyond what jose.ParseCompact's
// own splitting already covers. Only checks for panics/hangs.
func FuzzParseAccessToken(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate key: %v", err)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	bearer, _, err := IssueAccessToken(AccessTokenParams{
		Signer: key, Algorithm: fapi.ES256, KeyID: "fuzz-kid",
		Issuer: "https://as.example", Subject: "https://client.example",
		Audience: "https://resource.example", ClientID: "https://client.example",
		Scope: "openid profile", Now: now, Lifetime: time.Hour,
	})
	if err != nil {
		f.Fatalf("IssueAccessToken(bearer): %v", err)
	}

	dpopBound, _, err := IssueAccessToken(AccessTokenParams{
		Signer: key, Algorithm: fapi.ES256, KeyID: "fuzz-kid",
		Issuer: "https://as.example", Subject: "https://client.example",
		Audience: "https://resource.example", ClientID: "https://client.example",
		Now: now, Lifetime: time.Hour,
		Confirmation: &Confirmation{JKT: "fuzz-jwk-thumbprint"},
	})
	if err != nil {
		f.Fatalf("IssueAccessToken(dpop-bound): %v", err)
	}

	mtlsBound, _, err := IssueAccessToken(AccessTokenParams{
		Signer: key, Algorithm: fapi.ES256, KeyID: "fuzz-kid",
		Issuer: "https://as.example", Subject: "https://client.example",
		Audience: "https://resource.example", ClientID: "https://client.example",
		Now: now, Lifetime: time.Hour,
		Confirmation: &Confirmation{X5TS256: "fuzz-cert-thumbprint"},
	})
	if err != nil {
		f.Fatalf("IssueAccessToken(mtls-bound): %v", err)
	}

	f.Add(bearer)
	f.Add(dpopBound)
	f.Add(mtlsBound)
	f.Add("")
	f.Add(".")
	f.Add("a.b.c")

	f.Fuzz(func(t *testing.T, tok string) {
		_, _ = ParseAccessToken(tok)
	})
}

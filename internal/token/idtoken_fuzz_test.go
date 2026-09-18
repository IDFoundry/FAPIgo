package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
)

// FuzzParseIDToken exercises ParseIDToken against arbitrary strings —
// the single most central artifact a client parses client-side, from
// the token response, before any signature is checked. Exercises
// parseIDTokenClaims' own handling (nonce, auth_time, acr, amr, and
// at_hash — each of which OIDC Core attaches its own validation
// semantics to on the Validate side, in internal/token/validate.go)
// beyond what jose.ParseCompactMax's own splitting already covers.
// Only checks for panics/hangs.
func FuzzParseIDToken(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate key: %v", err)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	minimal, err := IssueIDToken(IDTokenParams{
		Signer: key, Algorithm: fapi.ES256, KeyID: "fuzz-kid",
		Issuer: "https://as.example", Subject: "https://user.example",
		Audience: "https://client.example", Now: now, Lifetime: time.Hour,
	})
	if err != nil {
		f.Fatalf("IssueIDToken(minimal): %v", err)
	}

	full, err := IssueIDToken(IDTokenParams{
		Signer: key, Algorithm: fapi.ES256, KeyID: "fuzz-kid",
		Issuer: "https://as.example", Subject: "https://user.example",
		Audience: "https://client.example", Now: now, Lifetime: time.Hour,
		Nonce: "fuzz-nonce", AuthTime: now.Add(-time.Minute),
		ACR: "urn:mace:incommon:iap:silver", AMR: []string{"pwd", "otp"},
		AccessToken: "fuzz-access-token",
	})
	if err != nil {
		f.Fatalf("IssueIDToken(full): %v", err)
	}

	f.Add(minimal)
	f.Add(full)
	f.Add("")
	f.Add(".")
	f.Add("a.b.c")

	f.Fuzz(func(t *testing.T, tok string) {
		_, _ = ParseIDToken(tok)
	})
}

package jarm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
)

// FuzzParseJARMResponse exercises Parse against arbitrary strings. A
// JARM response arrives via a redirect the browser controls, parsed
// client-side before any signature is checked — Response's own doc
// comment stresses that "an unverified error claim is exactly as
// untrustworthy as an unverified code claim," so both response shapes
// are seeded here. Exercises parseClaims' own handling on top of what
// jose.ParseCompact's own splitting already covers. Only checks for
// panics/hangs.
func FuzzParseJARMResponse(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate key: %v", err)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	success, err := Create(CreateParams{
		Signer: key, Algorithm: fapi.ES256, KeyID: "fuzz-kid",
		Issuer: "https://as.example", Audience: "https://client.example",
		Now: now, Lifetime: time.Minute,
		Parameters: map[string]json.RawMessage{
			"code":  json.RawMessage(`"fuzz-authorization-code"`),
			"state": json.RawMessage(`"fuzz-state"`),
		},
	})
	if err != nil {
		f.Fatalf("Create(success): %v", err)
	}

	errorResponse, err := Create(CreateParams{
		Signer: key, Algorithm: fapi.ES256, KeyID: "fuzz-kid",
		Issuer: "https://as.example", Audience: "https://client.example",
		Now: now, Lifetime: time.Minute,
		Parameters: map[string]json.RawMessage{
			"error":             json.RawMessage(`"access_denied"`),
			"error_description": json.RawMessage(`"fuzz description"`),
			"state":             json.RawMessage(`"fuzz-state"`),
		},
	})
	if err != nil {
		f.Fatalf("Create(error): %v", err)
	}

	f.Add(success)
	f.Add(errorResponse)
	f.Add("")
	f.Add(".")
	f.Add("a.b.c")

	f.Fuzz(func(t *testing.T, token string) {
		_, _ = Parse(token)
	})
}

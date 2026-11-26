package clientattestation

import (
	"errors"
	"strings"
	"testing"
)

// TestParsePoPClaimsRefusesDuplicateMembers: an attestation PoP is a
// JWT, whose claim names RFC 7519 §4 requires to be unique, like the
// attestation's own (TestParseAttestationClaimsRefusesDuplicateMembers).
// encoding/json keeps the last copy of a repeated one where another
// reader keeps the first, so a PoP that repeats a member with differing
// copies is refused. One whose copies are identical, which every reader
// reads alike, is accepted (unlike an attestation, whose cnf decodes
// into a struct, and which refuses any repeat).
func TestParsePoPClaimsRefusesDuplicateMembers(t *testing.T) {
	for _, payload := range []string{
		`{"iss":"c","aud":"a","jti":"j","iat":1}`,
		`{"iss":"c","aud":"a","jti":"j","iat":1,"jti":"j"}`,
	} {
		if _, err := parsePoPClaims([]byte(payload)); err != nil {
			t.Fatalf("parsePoPClaims(%s) = %v, want nil", payload, err)
		}
	}
	for _, payload := range []string{
		`{"iss":"c","aud":"https://other.example","jti":"j","iat":1,"aud":"a"}`,
		`{"iss":"c","aud":"a","jti":"j","iat":1,"jti":"k"}`,
	} {
		_, err := parsePoPClaims([]byte(payload))
		if !errors.Is(err, ErrMalformedClaims) || !strings.Contains(err.Error(), "duplicate member name") {
			t.Errorf("parsePoPClaims(%s) = %v, want ErrMalformedClaims for a duplicate member", payload, err)
		}
	}
}

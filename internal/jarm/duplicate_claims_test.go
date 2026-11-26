package jarm

import (
	"errors"
	"strings"
	"testing"
)

// TestParseClaimsRefusesDuplicateMembers: RFC 7519 §4 requires a JWT's
// claim names to be unique. encoding/json keeps the last copy of a
// repeated one, where a first-wins reader of the same JWT keeps the
// first, so the two would act on different claims. A claims set that
// repeats a member with differing copies, at any depth, or as a case
// variant, is refused. One that repeats a member with identical copies
// is accepted: an authorization server writing iss both as the JWT
// claim and as the RFC 9207 iss response parameter sends iss twice,
// with one value, which every reader reads alike.
func TestParseClaimsRefusesDuplicateMembers(t *testing.T) {
	for _, payload := range []string{
		`{"iss":"https://as.example","aud":"client-1","exp":9999999999,"code":"c"}`,
		`{"exp":9999999999,"aud":"client-1","code":"c","iss":"https://as.example","state":"s","iss":"https://as.example"}`,
	} {
		c, err := parseClaims([]byte(payload))
		if err != nil {
			t.Fatalf("parseClaims(%s) = %v, want nil", payload, err)
		}
		if c.Issuer != "https://as.example" {
			t.Fatalf("parseClaims(%s): Issuer = %q, want https://as.example", payload, c.Issuer)
		}
	}
	for _, payload := range []string{
		`{"iss":"https://evil.example","aud":"client-1","exp":9999999999,"code":"c","iss":"https://as.example"}`,
		`{"iss":"https://as.example","aud":"client-1","exp":9999999999,"code":"a","code":"b"}`,
		`{"iss":"https://as.example","aud":"client-1","exp":9999999999,"code":"c","ISS":"https://as.example"}`,
	} {
		_, err := parseClaims([]byte(payload))
		if !errors.Is(err, ErrMalformedClaims) || !strings.Contains(err.Error(), "duplicate member name") {
			t.Errorf("parseClaims(%s) = %v, want ErrMalformedClaims for a duplicate member", payload, err)
		}
	}
}

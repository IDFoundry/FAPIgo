package dpop

import (
	"errors"
	"strings"
	"testing"
)

// TestParseClaimsRefusesDuplicateMembers: RFC 7519 §4 requires a JWT's
// claim names to be unique. encoding/json keeps the last copy of a
// repeated one, where a first-wins reader of the same JWT keeps the
// first, so the two would act on different claims. A claims set that
// repeats a member with differing copies, at any depth, is refused; one
// whose copies are identical, which every reader reads alike, is
// accepted.
func TestParseClaimsRefusesDuplicateMembers(t *testing.T) {
	for _, payload := range []string{
		`{"jti":"j","htm":"POST","htu":"https://rs.example.com/","iat":1}`,
		`{"jti":"j","htm":"POST","htu":"https://rs.example.com/","iat":1,"htm":"POST"}`,
	} {
		if _, err := parseClaims([]byte(payload)); err != nil {
			t.Fatalf("parseClaims(%s) = %v, want nil", payload, err)
		}
	}
	for _, payload := range []string{
		`{"jti":"j","htm":"GET","htu":"https://rs.example.com/","iat":1,"htm":"POST"}`,
		`{"jti":"j","htm":"POST","htu":"https://other.example/","htu":"https://rs.example.com/","iat":1}`,
		`{"jti":"j","htm":"POST","htu":"https://rs.example.com/","iat":1,"HTM":"POST"}`,
	} {
		_, err := parseClaims([]byte(payload))
		if !errors.Is(err, ErrMalformedClaims) || !strings.Contains(err.Error(), "duplicate member name") {
			t.Errorf("parseClaims(%s) = %v, want ErrMalformedClaims for a duplicate member", payload, err)
		}
	}
}

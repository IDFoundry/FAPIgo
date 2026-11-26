package clientassertion

import (
	"errors"
	"strings"
	"testing"
)

// TestParseClaimsRefusesDuplicateMembers: RFC 7519 §4 requires a JWT's
// claim names to be unique. encoding/json keeps the last copy of a
// repeated one, where a first-wins reader of the same JWT keeps the
// first, so the two would act on different claims. A claims set that
// repeats a member, at any depth, is refused.
func TestParseClaimsRefusesDuplicateMembers(t *testing.T) {
	if _, err := parseClaims([]byte(`{"iss":"c","sub":"c","aud":"https://as.example.com","exp":2,"iat":1,"jti":"j"}`)); err != nil {
		t.Fatalf("parseClaims(valid) = %v, want nil", err)
	}
	for _, payload := range []string{
		`{"iss":"c","sub":"c","aud":"https://other.example","exp":2,"iat":1,"jti":"j","aud":"https://as.example.com"}`,
		`{"iss":"c","sub":"c","aud":"https://as.example.com","exp":2,"iat":1,"jti":"a","jti":"b"}`,
	} {
		_, err := parseClaims([]byte(payload))
		if !errors.Is(err, ErrMalformedClaims) || !strings.Contains(err.Error(), "duplicate member name") {
			t.Errorf("parseClaims(%s) = %v, want ErrMalformedClaims for a duplicate member", payload, err)
		}
	}
}

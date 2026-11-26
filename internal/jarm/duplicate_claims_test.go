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
// repeats a member, at any depth, is refused.
func TestParseClaimsRefusesDuplicateMembers(t *testing.T) {
	if _, err := parseClaims([]byte(`{"iss":"https://as.example","aud":"client-1","exp":9999999999,"code":"c"}`)); err != nil {
		t.Fatalf("parseClaims(valid) = %v, want nil", err)
	}
	for _, payload := range []string{
		`{"iss":"https://evil.example","aud":"client-1","exp":9999999999,"code":"c","iss":"https://as.example"}`,
		`{"iss":"https://as.example","aud":"client-1","exp":9999999999,"code":"a","code":"b"}`,
	} {
		_, err := parseClaims([]byte(payload))
		if !errors.Is(err, ErrMalformedClaims) || !strings.Contains(err.Error(), "duplicate member name") {
			t.Errorf("parseClaims(%s) = %v, want ErrMalformedClaims for a duplicate member", payload, err)
		}
	}
}

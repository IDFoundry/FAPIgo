package requestobject

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
	if _, err := parseClaims([]byte(`{"iss":"client-123","aud":"https://as.example","exp":4102444800,"scope":"openid"}`)); err != nil {
		t.Fatalf("parseClaims(valid) = %v, want nil", err)
	}
	for _, payload := range []string{
		`{"iss":"client-123","aud":"https://as.example","exp":4102444800,"scope":"openid","scope":"openid payments"}`,
		`{"iss":"client-123","aud":"https://as.example","exp":4102444800,"claims":{"id_token":{"acr":{"value":"a"},"acr":{"value":"b"}}}}`,
	} {
		_, err := parseClaims([]byte(payload))
		if !errors.Is(err, ErrMalformedClaims) || !strings.Contains(err.Error(), "duplicate member name") {
			t.Errorf("parseClaims(%s) = %v, want ErrMalformedClaims for a duplicate member", payload, err)
		}
	}
}

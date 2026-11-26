package token

import (
	"errors"
	"testing"
)

// TestDecodeClaimsObjectRefusesANonObject: a claims set that is valid
// JSON with no repeated member, but not a JSON object, is malformed.
func TestDecodeClaimsObjectRefusesANonObject(t *testing.T) {
	for _, payload := range []string{`[]`, `"claims"`, `7`} {
		if _, err := decodeClaimsObject([]byte(payload)); !errors.Is(err, ErrMalformedClaims) {
			t.Errorf("decodeClaimsObject(%s) = %v, want ErrMalformedClaims", payload, err)
		}
	}
}

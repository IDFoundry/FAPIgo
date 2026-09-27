package dpop

import (
	"strings"
	"testing"
)

func TestParseClaimsRejectsCaseVariantMemberNames(t *testing.T) {
	_, err := parseClaims([]byte(`{"jti":"j","HTM":"POST","htu":"https://rs.example.com/","iat":1}`))
	if err == nil || !strings.Contains(err.Error(), "case-sensitive") {
		t.Fatalf("err = %v, want case-sensitivity rejection", err)
	}
}

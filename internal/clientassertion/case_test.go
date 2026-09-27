package clientassertion

import (
	"strings"
	"testing"
)

func TestParseClaimsRejectsCaseVariantMemberNames(t *testing.T) {
	_, err := parseClaims([]byte(`{"ISS":"c","sub":"c","aud":"https://as.example.com","exp":2,"iat":1,"jti":"j"}`))
	if err == nil || !strings.Contains(err.Error(), "case-sensitive") {
		t.Fatalf("err = %v, want case-sensitivity rejection", err)
	}
}

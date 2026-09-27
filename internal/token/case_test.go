package token

import (
	"strings"
	"testing"
)

func TestParseAccessTokenClaimsRejectsCaseVariantCnfMember(t *testing.T) {
	_, err := parseAccessTokenClaims([]byte(`{"iss":"https://as.example.com","sub":"s","aud":"https://rs.example.com","exp":2,"iat":1,"jti":"j","client_id":"c","cnf":{"JKT":"x"}}`))
	if err == nil || !strings.Contains(err.Error(), "case-sensitive") {
		t.Fatalf("err = %v, want case-sensitivity rejection", err)
	}
}

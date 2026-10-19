package clientattestation

import (
	"strings"
	"testing"
)

func TestParseAttestationClaims_RejectsMalformedJSON(t *testing.T) {
	if _, err := parseAttestationClaims([]byte("not json")); err == nil {
		t.Errorf("parseAttestationClaims accepted malformed JSON")
	}
}

func TestParseAttestationClaims_RejectsMissingRequiredFields(t *testing.T) {
	cases := map[string]string{
		"missing sub": `{"iss":"a","exp":1,"cnf":{"jwk":{}}}`,
		"missing exp": `{"iss":"a","sub":"c","cnf":{"jwk":{}}}`,
		"missing cnf": `{"iss":"a","sub":"c","exp":1}`,
	}
	for name, payload := range cases {
		if _, err := parseAttestationClaims([]byte(payload)); err == nil {
			t.Errorf("%s: parseAttestationClaims accepted claims missing a required field", name)
		}
	}
}

func TestParsePoPClaims_RejectsMalformedJSON(t *testing.T) {
	if _, err := parsePoPClaims([]byte("not json")); err == nil {
		t.Errorf("parsePoPClaims accepted malformed JSON")
	}
}

func TestParsePoPClaims_RejectsMissingRequiredFields(t *testing.T) {
	cases := map[string]string{
		"missing aud": `{"iss":"c","jti":"j","iat":1}`,
		"missing jti": `{"iss":"c","aud":"a","iat":1}`,
		"missing iat": `{"iss":"c","aud":"a","jti":"j"}`,
	}
	for name, payload := range cases {
		if _, err := parsePoPClaims([]byte(payload)); err == nil {
			t.Errorf("%s: parsePoPClaims accepted claims missing a required field", name)
		}
	}
}

// TestParseClaimsWithoutIss: draft-08 removed iss from both JWTs, so its
// absence is no longer malformed (draft-12 §4, §5.1).
func TestParseClaimsWithoutIss(t *testing.T) {
	if _, err := parseAttestationClaims([]byte(`{"sub":"c","exp":1,"iat":1,"cnf":{"jwk":{}}}`)); err != nil {
		t.Errorf("parseAttestationClaims without iss: %v", err)
	}
	if _, err := parsePoPClaims([]byte(`{"aud":"a","jti":"j","iat":1}`)); err != nil {
		t.Errorf("parsePoPClaims without iss: %v", err)
	}
}

// TestParsePoPClaimsAudience: aud is one audience, as a string or an
// array holding just that string (RFC 7519 §4.1.3); a PoP is "intended
// for a single audience" (draft-12 §5.1), so an array naming more, or
// none, is malformed.
func TestParsePoPClaimsAudience(t *testing.T) {
	for payload, want := range map[string]string{
		`{"aud":"https://as.example.com","jti":"j","iat":1}`:      "https://as.example.com",
		`{"aud":["https://as.example.com"],"jti":"j","iat":1}`:    "https://as.example.com",
		`{"aud": [ "https://as.example.com" ],"jti":"j","iat":1}`: "https://as.example.com",
	} {
		c, err := parsePoPClaims([]byte(payload))
		if err != nil || string(c.Audience) != want {
			t.Errorf("parsePoPClaims(%s) = (%q, %v), want %q", payload, c.Audience, err, want)
		}
	}
	for _, payload := range []string{
		`{"aud":["https://as.example.com","https://other.example.com"],"jti":"j","iat":1}`,
		`{"aud":[],"jti":"j","iat":1}`,
		`{"aud":[""],"jti":"j","iat":1}`,
		`{"aud":null,"jti":"j","iat":1}`,
		`{"aud":[1],"jti":"j","iat":1}`,
		`{"aud":1,"jti":"j","iat":1}`,
		`{"aud":{},"jti":"j","iat":1}`,
	} {
		if _, err := parsePoPClaims([]byte(payload)); err == nil {
			t.Errorf("parsePoPClaims(%s) accepted it", payload)
		}
	}
}

func TestParseClaimsRejectCaseVariantMemberNames(t *testing.T) {
	if _, err := parseAttestationClaims([]byte(`{"iss":"a","sub":"c","exp":1,"cnf":{"JWK":{}}}`)); err == nil || !strings.Contains(err.Error(), "case-sensitive") {
		t.Errorf("parseAttestationClaims: err = %v, want case-sensitivity rejection", err)
	}
	if _, err := parsePoPClaims([]byte(`{"ISS":"c","aud":"https://as.example.com","jti":"j","iat":1}`)); err == nil || !strings.Contains(err.Error(), "case-sensitive") {
		t.Errorf("parsePoPClaims: err = %v, want case-sensitivity rejection", err)
	}
}

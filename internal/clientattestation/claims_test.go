package clientattestation

import "testing"

func TestParseAttestationClaims_RejectsMalformedJSON(t *testing.T) {
	if _, err := parseAttestationClaims([]byte("not json")); err == nil {
		t.Errorf("parseAttestationClaims accepted malformed JSON")
	}
}

func TestParseAttestationClaims_RejectsMissingRequiredFields(t *testing.T) {
	cases := map[string]string{
		"missing iss": `{"sub":"c","exp":1,"cnf":{"jwk":{}}}`,
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
		"missing iss": `{"aud":"a","jti":"j","iat":1}`,
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

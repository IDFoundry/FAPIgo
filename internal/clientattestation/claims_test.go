package clientattestation

import (
	"errors"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
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

// TestParseAttestationClaimsRefusesDuplicateMembers covers RFC 7519 §4:
// claim names are unique. encoding/json merged two copies of cnf,
// keeping the first's jwk where VerifiedAttestation.Claims, like another
// implementation, kept the last copy, and checked the case of the last
// copy alone; now any repeated name, at any depth, is malformed.
func TestParseAttestationClaimsRefusesDuplicateMembers(t *testing.T) {
	for name, payload := range map[string]string{
		"cnf then empty cnf":             `{"sub":"c","exp":1,"cnf":{"jwk":{"kty":"EC"}},"cnf":{}}`,
		"case variant in a non-last cnf": `{"sub":"c","exp":1,"cnf":{"JWK":{"kty":"EC"}},"cnf":{}}`,
		"jwk twice inside cnf":           `{"sub":"c","exp":1,"cnf":{"jwk":{"kty":"EC"},"jwk":{"kty":"RSA"}}}`,
		"sub twice":                      `{"sub":"c","sub":"d","exp":1,"cnf":{"jwk":{}}}`,
	} {
		_, err := parseAttestationClaims([]byte(payload))
		if !errors.Is(err, ErrMalformedClaims) || !strings.Contains(err.Error(), "duplicate member") {
			t.Errorf("%s: parseAttestationClaims = %v, want ErrMalformedClaims for a duplicate member", name, err)
		}
	}
}

// TestParseRefusesDuplicateConfirmation is the same through Parse: a
// signed attestation repeating cnf is malformed before any key is
// looked up for it, while the same attestation with one cnf parses.
func TestParseRefusesDuplicateConfirmation(t *testing.T) {
	key := generateKey(t)
	cnf := `{"jwk":` + string(confirmationJWK(t, &key.PublicKey)) + `}`
	for name, tc := range map[string]struct {
		claims string
		want   error // nil: Parse succeeds
	}{
		"once":  {`{"sub":"c","exp":1,"cnf":` + cnf + `}`, nil},
		"twice": {`{"sub":"c","exp":1,"cnf":` + cnf + `,"cnf":{}}`, ErrMalformedClaims},
	} {
		compact, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256, Type: TypHeader}, []byte(tc.claims))
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if _, err := Parse(compact); !errors.Is(err, tc.want) {
			t.Errorf("%s: Parse = %v, want %v", name, err, tc.want)
		}
	}
}

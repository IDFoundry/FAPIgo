package clientassertion

import (
	"encoding/base64"
	"errors"
	"fmt"
	"testing"

	"github.com/idfoundry/fapigo/internal/jose"
)

func TestParseRefusesOtherExplicitTypes(t *testing.T) {
	enc := base64.RawURLEncoding.EncodeToString
	payload := `{"iss":"client-1","sub":"client-1","aud":"https://as.example.com","exp":2000000000,"iat":1000000000,"jti":"j"}`
	for typ, refused := range map[string]bool{
		"":                                      false,
		"JWT":                                   false,
		"client-authentication+jwt":             false,
		"application/client-authentication+jwt": false,
		"oauth-authz-req+jwt":                   true,
		"dpop+jwt":                              true,
		"oauth-client-attestation-pop+jwt":      true,
		"at+jwt":                                true,
	} {
		t.Run(typ, func(t *testing.T) {
			header := `{"alg":"ES256"}`
			if typ != "" {
				header = fmt.Sprintf(`{"alg":"ES256","typ":%q}`, typ)
			}
			_, err := Parse(enc([]byte(header)) + "." + enc([]byte(payload)) + "." + enc(make([]byte, 64)))
			if errors.Is(err, jose.ErrOtherExplicitType) != refused {
				t.Fatalf("Parse(typ %q) error = %v, want refused = %v", typ, err, refused)
			}
			if !refused && err != nil {
				t.Fatalf("Parse(typ %q) = %v, want nil", typ, err)
			}
		})
	}
}

// TestExplicitlyTyped: an assertion is explicitly typed when its typ is
// client-authentication+jwt, the RFC 10070 §4 type, compared as RFC
// 7515 §4.1.9 compares media types. No typ, a generic one (JWT, JOSE),
// a parameterized one, or a type this package doesn't know isn't.
func TestExplicitlyTyped(t *testing.T) {
	enc := base64.RawURLEncoding.EncodeToString
	payload := enc([]byte(`{"iss":"client-1","sub":"client-1","aud":"https://as.example.com","exp":2000000000,"iat":1000000000,"jti":"j"}`))
	for typ, want := range map[string]bool{
		"":                                      false,
		"JWT":                                   false,
		"jwt":                                   false,
		"application/jwt":                       false,
		"JOSE":                                  false,
		"JWT; charset=utf-8":                    false,
		"example-client-authentication+jwt":     false,
		"client-authentication+jwt":             true,
		"Client-Authentication+JWT":             true,
		"application/client-authentication+jwt": true,
	} {
		header := `{"alg":"ES256"}`
		if typ != "" {
			header = fmt.Sprintf(`{"alg":"ES256","typ":%q}`, typ)
		}
		parsed, err := Parse(enc([]byte(header)) + "." + payload + "." + enc(make([]byte, 64)))
		if err != nil {
			t.Fatalf("Parse(typ %q): %v", typ, err)
		}
		if got := parsed.ExplicitlyTyped(); got != want {
			t.Errorf("ExplicitlyTyped() for typ %q = %v, want %v", typ, got, want)
		}
	}
}

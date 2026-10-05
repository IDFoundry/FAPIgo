package token

import (
	"encoding/base64"
	"errors"
	"fmt"
	"testing"

	"github.com/idfoundry/fapigo/internal/jose"
)

// unsignedCompact builds a compact JWS with the given header and
// payload JSON and a dummy signature: enough for the Parse functions,
// which don't verify.
func unsignedCompact(header, payload string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(header)) + "." + enc([]byte(payload)) + "." + enc(make([]byte, 64))
}

func typHeader(typ string) string {
	if typ == "" {
		return `{"alg":"ES256"}`
	}
	return fmt.Sprintf(`{"alg":"ES256","typ":%q}`, typ)
}

func TestParseIDTokenRefusesOtherExplicitTypes(t *testing.T) {
	payload := `{"iss":"https://op.example.com","sub":"user","aud":"rp","exp":2000000000,"iat":1000000000}`
	for typ, refused := range map[string]bool{
		"":                    false,
		"JWT":                 false,
		"application/jwt":     false,
		"at+jwt":              true,
		"application/AT+JWT":  true,
		"logout+jwt":          true,
		"oauth-authz-req+jwt": true,
	} {
		t.Run(typ, func(t *testing.T) {
			_, err := ParseIDToken(unsignedCompact(typHeader(typ), payload))
			if got := errors.Is(err, jose.ErrOtherExplicitType); got != refused {
				t.Fatalf("ParseIDToken(typ %q) error = %v, want refused = %v", typ, err, refused)
			}
			if !refused && err != nil {
				t.Fatalf("ParseIDToken(typ %q) = %v, want nil", typ, err)
			}
		})
	}
}

// TestParseAccessTokenAcceptsAtJWTMediaTypeForms: RFC 9068 §4 has a
// resource server accept "at+jwt" or "application/at+jwt"; media types
// compare case-insensitively (RFC 7515 §4.1.9).
func TestParseAccessTokenAcceptsAtJWTMediaTypeForms(t *testing.T) {
	payload := `{"iss":"https://as.example.com","sub":"user","aud":"https://rs.example.com","exp":2000000000,"iat":1000000000,"jti":"j","client_id":"c"}`
	for typ, ok := range map[string]bool{
		"at+jwt":             true,
		"application/at+jwt": true,
		"AT+JWT":             true,
		"":                   false,
		"JWT":                false,
		"dpop+jwt":           false,
	} {
		t.Run(typ, func(t *testing.T) {
			_, err := ParseAccessToken(unsignedCompact(typHeader(typ), payload))
			if ok && err != nil {
				t.Fatalf("ParseAccessToken(typ %q) = %v, want nil", typ, err)
			}
			if !ok && !errors.Is(err, ErrWrongType) {
				t.Fatalf("ParseAccessToken(typ %q) = %v, want ErrWrongType", typ, err)
			}
		})
	}
}

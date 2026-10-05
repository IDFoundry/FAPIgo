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
			if got := errors.Is(err, jose.ErrOtherExplicitType); got != refused {
				t.Fatalf("Parse(typ %q) error = %v, want refused = %v", typ, err, refused)
			}
			if !refused && err != nil {
				t.Fatalf("Parse(typ %q) = %v, want nil", typ, err)
			}
		})
	}
}

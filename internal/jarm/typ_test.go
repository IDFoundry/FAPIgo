package jarm

import (
	"encoding/base64"
	"errors"
	"fmt"
	"testing"

	"github.com/idfoundry/fapigo/internal/jose"
)

func TestParseRefusesOtherExplicitTypes(t *testing.T) {
	enc := base64.RawURLEncoding.EncodeToString
	payload := `{"iss":"https://as.example.com","aud":"client-1","exp":2000000000,"code":"c","state":"s"}`
	for typ, refused := range map[string]bool{
		"":             false,
		"JWT":          false,
		"at+jwt":       true,
		"secevent+jwt": true,
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

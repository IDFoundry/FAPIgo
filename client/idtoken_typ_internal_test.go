package client

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
)

// TestValidateIDTokenAcceptsOnlyGenericTypes: an ID token's typ is
// absent or "JWT" — what the OpenID Foundation conformance suite sends —
// and an issuer-signed JWT of any other kind for the same client, an
// SD-JWT credential or a status list token say, isn't taken for one,
// even when its typ is one no list of known kinds would name.
func TestValidateIDTokenAcceptsOnlyGenericTypes(t *testing.T) {
	now := time.Now()
	c, idKey := idTokenTestClient(t, now, Algorithms{IDToken: fapi.ES256}, nil)
	payload, err := json.Marshal(map[string]any{
		"iss": idTokenTestIssuer, "sub": idTokenTestSubject, "aud": idTokenTestClientID,
		"nonce": idTokenTestNonce, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for typ, refused := range map[string]bool{
		"":                  false,
		"JWT":               false,
		"application/jwt":   false,
		"dc+sd-jwt":         true,
		"vc+sd-jwt":         true,
		"statuslist+jwt":    true,
		"at+jwt; charset=x": true,
		"logout+jwt":        true,
	} {
		t.Run(typ, func(t *testing.T) {
			raw, err := jose.Sign(idKey, jose.Header{Algorithm: fapi.ES256, KeyID: "as-kid", Type: typ}, payload)
			if err != nil {
				t.Fatalf("jose.Sign: %v", err)
			}
			_, verr := c.validateIDToken(context.Background(), raw, "", idTokenTestNonce)
			if verr == nil {
				if refused {
					t.Fatalf("validateIDToken(typ %q) = nil, want refusal", typ)
				}
				return
			}
			if !refused || !errors.Is(verr, jose.ErrUnexpectedType) {
				t.Fatalf("validateIDToken(typ %q) = %v, want refused = %v", typ, verr, refused)
			}
		})
	}
}

package requestobject

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
)

// FuzzParseRequestObject exercises Parse against arbitrary strings. A
// request object is client-supplied (RFC 9101), parsed before any
// signature is checked — Parse's own doc comment on Object explicitly
// frames every accessor as "safe... only because it only selects what
// to check against, not what to trust." Exercises parseClaims' own
// handling (aud as either a bare string or an array — both normalized
// the same way, per Claims.Audience's own doc comment — plus the
// client_id/iss cross-check and the sub-presence tracking OpenID
// Federation 1.0 §12.1.1 needs) beyond what jose.ParseCompact's own
// splitting already covers. Only checks for panics/hangs.
func FuzzParseRequestObject(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate key: %v", err)
	}
	sign := func(payload string) string {
		f.Helper()
		token, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256, Type: "oauth-authz-req+jwt"}, []byte(payload))
		if err != nil {
			f.Fatalf("sign: %v", err)
		}
		return token
	}

	minimal := sign(`{"iss":"https://client.example","aud":"https://as.example","exp":4102444800}`)
	arrayAudience := sign(`{"iss":"https://client.example","aud":["https://as.example","https://other.example"],"exp":4102444800}`)
	full := sign(`{"iss":"https://client.example","aud":"https://as.example","exp":4102444800,"nbf":1735689600,"iat":1735689600,"jti":"fuzz-jti","client_id":"https://client.example","response_type":"code","scope":"openid"}`)
	withSub := sign(`{"iss":"https://client.example","aud":"https://as.example","exp":4102444800,"sub":"https://client.example"}`)
	clientIDMismatch := sign(`{"iss":"https://client.example","aud":"https://as.example","exp":4102444800,"client_id":"https://someone-else.example"}`)

	wrongType, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256, Type: "not-oauth-authz-req+jwt"}, []byte(`{}`))
	if err != nil {
		f.Fatalf("sign wrong-type token: %v", err)
	}
	untyped, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256}, []byte(`{"iss":"https://client.example","aud":"https://as.example","exp":4102444800}`))
	if err != nil {
		f.Fatalf("sign untyped token: %v", err)
	}

	f.Add(minimal)
	f.Add(arrayAudience)
	f.Add(full)
	f.Add(withSub)
	f.Add(clientIDMismatch)
	f.Add(wrongType)
	f.Add(untyped)
	f.Add("")
	f.Add(".")
	f.Add("a.b.c")

	f.Fuzz(func(t *testing.T, token string) {
		_, _ = Parse(token)
	})
}

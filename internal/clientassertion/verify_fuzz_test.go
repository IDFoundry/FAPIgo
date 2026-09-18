package clientassertion

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
)

// FuzzParseClientAssertion exercises Parse against arbitrary strings —
// a client assertion is client-supplied (RFC 7523), parsed before any
// signature is checked. Unlike clientattestation's own claims,
// parseClaims here calls json.Decoder.DisallowUnknownFields — an
// unrecognized claim name is itself a rejection, a shape no other fuzz
// target in this repo reaches. Only checks for panics/hangs.
func FuzzParseClientAssertion(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate key: %v", err)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	valid, err := CreateAssertion(AssertionRequest{
		Signer: key, Algorithm: fapi.ES256, KeyID: "fuzz-kid",
		ClientID: "https://client.example", Audience: "https://as.example/token",
		Now: now, Lifetime: time.Minute,
	})
	if err != nil {
		f.Fatalf("CreateAssertion: %v", err)
	}

	unknownField, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256}, []byte(`{"iss":"https://client.example","sub":"https://client.example","aud":"https://as.example/token","jti":"x","exp":4102444800,"unexpected":"field"}`))
	if err != nil {
		f.Fatalf("sign unknown-field token: %v", err)
	}
	arrayAudience, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256}, []byte(`{"iss":"https://client.example","sub":"https://client.example","aud":["https://as.example/token"],"jti":"x","exp":4102444800}`))
	if err != nil {
		f.Fatalf("sign array-audience token: %v", err)
	}

	f.Add(valid)
	f.Add(unknownField)
	f.Add(arrayAudience)
	f.Add("")
	f.Add(".")
	f.Add("a.b.c")

	f.Fuzz(func(t *testing.T, assertion string) {
		_, _ = Parse(assertion)
	})
}

package clientattestation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
)

// FuzzParseClientAttestation exercises Parse against arbitrary strings.
// A Client Attestation JWT is issued out of band by an external
// Attester (this package never creates one, only parses/verifies), and
// is client-supplied at the protocol boundary — parsed before any
// signature is checked. Unlike clientassertion's own claims,
// attestationClaims deliberately tolerates unrecognized fields
// (draft-07 §5.1 rule 1) rather than rejecting them, and carries a
// nested "cnf.jwk" object this package leaves as raw JSON. Only checks
// for panics/hangs.
func FuzzParseClientAttestation(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate key: %v", err)
	}
	jwk, err := jose.NewJWK(&key.PublicKey, fapi.ES256)
	if err != nil {
		f.Fatalf("NewJWK: %v", err)
	}
	jwkJSON, err := jwk.MarshalJSON()
	if err != nil {
		f.Fatalf("marshal jwk: %v", err)
	}

	valid, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256, Type: TypHeader},
		[]byte(`{"iss":"https://attester.example","sub":"https://client.example","exp":4102444800,"cnf":{"jwk":`+string(jwkJSON)+`}}`))
	if err != nil {
		f.Fatalf("sign valid attestation: %v", err)
	}
	unrecognizedField, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256, Type: TypHeader},
		[]byte(`{"iss":"https://attester.example","sub":"https://client.example","exp":4102444800,"cnf":{"jwk":`+string(jwkJSON)+`},"some_future_claim":"ignored"}`))
	if err != nil {
		f.Fatalf("sign attestation with unrecognized field: %v", err)
	}
	missingCNF, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256, Type: TypHeader},
		[]byte(`{"iss":"https://attester.example","sub":"https://client.example","exp":4102444800}`))
	if err != nil {
		f.Fatalf("sign attestation missing cnf: %v", err)
	}

	f.Add(valid)
	f.Add(unrecognizedField)
	f.Add(missingCNF)
	f.Add("")
	f.Add(".")
	f.Add("a.b.c")

	f.Fuzz(func(t *testing.T, attestation string) {
		_, _ = Parse(attestation)
	})
}

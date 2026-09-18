package jose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"

	fapi "github.com/idfoundry/fapigo"
)

// FuzzParseJWKSet exercises ParseJWKSet against arbitrary bytes — the
// entry point for a JWK Set fetched over the network, either directly
// (client/server issuer-key discovery) or as part of an OpenID
// Federation Entity Statement's own "jwks" member. Only checks for
// panics/hangs: ParseJWKSet's own documented contract is that a
// malformed or unsupported entry is skipped rather than surfaced, so
// there is no useful correctness oracle here beyond "never crashes,
// never loops" — the property-style checks belong on ParseJWK itself
// (see FuzzParseJWK).
func FuzzParseJWKSet(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate key: %v", err)
	}
	jwk, err := NewJWK(&key.PublicKey, fapi.ES256)
	if err != nil {
		f.Fatalf("NewJWK: %v", err)
	}
	entry, err := jwk.WithKeyID("fuzz-seed").MarshalJSON()
	if err != nil {
		f.Fatalf("marshal jwk: %v", err)
	}
	validSet, err := json.Marshal(map[string]any{"keys": []json.RawMessage{entry}})
	if err != nil {
		f.Fatalf("marshal jwks body: %v", err)
	}

	f.Add(validSet)
	f.Add([]byte(`{"keys":[]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(`{"keys":"not an array"}`))
	f.Add([]byte(`{"keys":[{"kty":"unknown"},null,123,"str"]}`))
	f.Add([]byte(`{"keys":[{"kty":"RSA","n":"AQ","e":"AQ","x5c":["!!!"]}]}`))

	f.Fuzz(func(t *testing.T, body []byte) {
		_, _ = ParseJWKSet(body)
	})
}

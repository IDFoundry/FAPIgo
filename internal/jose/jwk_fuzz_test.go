package jose

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	fapi "github.com/idfoundry/fapigo"
)

// FuzzParseJWK exercises ParseJWK against arbitrary bytes, under every
// algorithm this module supports — the entry point that turns untrusted
// wire data (a JWK embedded in a DPoP/request-object header, or one
// entry of a JWK Set fetched from a remote issuer) into a usable public
// key. Only checks for panics/hangs: ParseJWK is expected to reject
// almost everything the fuzzer generates, so there is no useful oracle
// beyond "never crashes, never loops".
func FuzzParseJWK(f *testing.F) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate ecdsa key: %v", err)
	}
	ecJWK, err := NewJWK(&ecKey.PublicKey, fapi.ES256)
	if err != nil {
		f.Fatalf("NewJWK(ec): %v", err)
	}
	ecData, err := ecJWK.MarshalJSON()
	if err != nil {
		f.Fatalf("marshal ec jwk: %v", err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatalf("generate rsa key: %v", err)
	}
	rsaJWK, err := NewJWK(&rsaKey.PublicKey, fapi.PS256)
	if err != nil {
		f.Fatalf("NewJWK(rsa): %v", err)
	}
	rsaData, err := rsaJWK.MarshalJSON()
	if err != nil {
		f.Fatalf("marshal rsa jwk: %v", err)
	}

	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatalf("generate ed25519 key: %v", err)
	}
	edJWK, err := NewJWK(edPriv.Public(), fapi.EdDSA)
	if err != nil {
		f.Fatalf("NewJWK(ed25519): %v", err)
	}
	edData, err := edJWK.MarshalJSON()
	if err != nil {
		f.Fatalf("marshal ed25519 jwk: %v", err)
	}

	f.Add(ecData)
	f.Add(rsaData)
	f.Add(edData)
	f.Add([]byte(`{}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(`{"kty":"EC","crv":"P-256","x":"","y":""}`))
	f.Add([]byte(`{"kty":"RSA","n":"AQ","e":"AQ"}`))
	f.Add([]byte(`{"kty":"OKP","crv":"Ed25519","x":"AQ"}`))
	f.Add([]byte(`{"kty":"RSA","n":"AQAB","e":"AQAB","d":"AQAB"}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		for _, alg := range []fapi.SignatureAlgorithm{fapi.ES256, fapi.PS256, fapi.EdDSA} {
			_, _ = ParseJWK(data, alg)
		}
	})
}

package jose

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	fapi "github.com/idfoundry/fapigo"
)

// FuzzThumbprintSurvivesReencoding is the oracle for the package doc's
// JWK encoding invariant: whatever spelling ParseJWK accepts, RSA
// leading zero octets among them, the key it returns re-encodes through
// MarshalJSON as a JWK that ParseJWK accepts again, with the same
// Thumbprint, and whose MarshalJSON is unchanged. A DPoP jkt, a replay
// key or a derived kid so never depends on how the key was written. An
// EC key it accepts was spelled exactly as MarshalJSON spells it: an EC
// key has one spelling.
func FuzzThumbprintSurvivesReencoding(f *testing.F) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate ecdsa key: %v", err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatalf("generate rsa key: %v", err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	n := rsaKey.N.Bytes()
	x, y := ec.X.FillBytes(make([]byte, 32)), ec.Y.FillBytes(make([]byte, 32))
	for _, seed := range []string{
		fmt.Sprintf(`{"kty":"EC","crv":"P-256","x":%q,"y":%q}`, enc(x), enc(y)),
		fmt.Sprintf(`{"kty":"EC","crv":"P-256","x":%q,"y":%q}`, enc(append([]byte{0}, x...)), enc(y)),
		fmt.Sprintf(`{"kty":"RSA","n":%q,"e":"AQAB"}`, enc(n)),
		fmt.Sprintf(`{"kty":"RSA","n":%q,"e":"AQAB"}`, enc(append([]byte{0}, n...))),
		fmt.Sprintf(`{"kty":"RSA","n":%q,"e":"AAEAAQ","kid":"k","use":"sig"}`, enc(n)),
		fmt.Sprintf(`{"kty":"RSA","n":%q,"e":"AAABAAE"}`, enc(n)),
		`{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, alg := range []fapi.SignatureAlgorithm{fapi.ES256, fapi.PS256, fapi.EdDSA} {
			checkThumbprintSurvivesReencoding(t, data, alg)
		}
	})
}

// checkThumbprintSurvivesReencoding checks FuzzThumbprintSurvivesReencoding's
// oracle for data parsed as a key for alg, if ParseJWK accepts it.
func checkThumbprintSurvivesReencoding(t *testing.T, data []byte, alg fapi.SignatureAlgorithm) {
	t.Helper()
	parsed, err := ParseJWK(data, alg)
	if err != nil {
		return
	}
	encoded, want := marshalAndThumbprint(t, parsed)
	again, err := ParseJWK(encoded, alg)
	if err != nil {
		t.Fatalf("ParseJWK(MarshalJSON(ParseJWK(%q))) = %v", data, err)
	}
	reencoded, got := marshalAndThumbprint(t, again)
	if got != want || !bytes.Equal(reencoded, encoded) {
		t.Fatalf("%q: Thumbprint %s, MarshalJSON %s; re-encoded, %s and %s", data, want, encoded, got, reencoded)
	}
	if _, ok := parsed.PublicKey().(*ecdsa.PublicKey); ok {
		checkECSpelling(t, data, encoded)
	}
}

// checkECSpelling wants an EC JWK that ParseJWK accepted, data, to give
// "x" and "y" exactly as encoded, its MarshalJSON, writes them: at the
// curve's full size, in canonical base64url. ParseJWK refuses a case
// variant of either name, so encoding/json reads the members it read.
func checkECSpelling(t *testing.T, data, encoded []byte) {
	t.Helper()
	var got, want struct {
		X string `json:"x"`
		Y string `json:"y"`
	}
	if json.Unmarshal(data, &got) != nil || json.Unmarshal(encoded, &want) != nil || got != want {
		t.Fatalf("%q: ParseJWK accepted x %q and y %q, but MarshalJSON writes %q and %q", data, got.X, got.Y, want.X, want.Y)
	}
}

package keys

import (
	"crypto"
	"testing"

	"github.com/idfoundry/fapigo/internal/jose"
)

// FuzzParseJWKSDocument checks parseJWKSDocument, which reads the JWK
// Set an authorization server publishes at its jwks_uri, never panics
// and is exactly jose.ParseTrustedJWKSet's reading (FuzzJWKSetRoles
// checks that one's per-key rules) carried over key for key: the same
// verdict, the same keys in the same order, each with its key ID,
// algorithm and public key.
func FuzzParseJWKSDocument(f *testing.F) {
	f.Add([]byte(`{"keys":[{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","kid":"a"}]}`))
	f.Add([]byte(`{"keys":[{"kty":"EC","crv":"P-256","x":"AQ","y":"AQ"},{"kty":"RSA","n":"AQ","e":"AQAB","use":"enc"}]}`))
	f.Add([]byte(`{"keys":[]}`))
	f.Add([]byte(`{"Keys":[]}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		got, err := parseJWKSDocument(body)
		want, wantErr := jose.ParseTrustedJWKSet(body)
		if (err == nil) != (wantErr == nil) || len(got) != len(want) {
			t.Fatalf("parseJWKSDocument(%q) = %d keys, %v; ParseTrustedJWKSet = %d keys, %v", body, len(got), err, len(want), wantErr)
		}
		for i, k := range got {
			w := want[i]
			if k.KeyID != w.KeyID || k.Algorithm != w.Algorithm || !k.PublicKey.(interface{ Equal(crypto.PublicKey) bool }).Equal(w.PublicKey) {
				t.Fatalf("key %d of %q = %+v, want %+v", i, body, k, w)
			}
		}
	})
}

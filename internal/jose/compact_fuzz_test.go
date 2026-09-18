package jose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	fapi "github.com/idfoundry/fapigo"
)

// FuzzParseCompact exercises ParseCompact/ParseCompactMax against
// arbitrary strings — the entry point every other package in this
// module ultimately goes through to split and base64url-decode a
// compact JWS, so a panic or hang here would be reachable from
// essentially any caller that accepts a bearer token, DPoP proof,
// client assertion, or request object. A successfully parsed value must
// also survive a Verify call without panicking, whether or not the
// signature actually checks out — that's the one property this target
// checks beyond "does not crash".
func FuzzParseCompact(f *testing.F) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate key: %v", err)
	}
	valid, err := Sign(priv, Header{Algorithm: fapi.ES256, Type: "test+jwt"}, []byte(`{"hello":"world"}`))
	if err != nil {
		f.Fatalf("sign: %v", err)
	}

	f.Add(valid)
	f.Add("")
	f.Add(".")
	f.Add("..")
	f.Add("a.b.c")
	f.Add("a.b.c.d")
	f.Add(valid + ".")
	f.Add(valid[:len(valid)-1])
	f.Add("eyJhbGciOiJub25lIn0.e30.")

	f.Fuzz(func(t *testing.T, s string) {
		compact, err := ParseCompact(s)
		if err != nil {
			return
		}
		_ = compact.Verify(&priv.PublicKey, fapi.ES256)
	})
}

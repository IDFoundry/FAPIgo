package server_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/server"
)

// TestNewValidatesStaticAttesterKeys: New refuses a keys.StaticAttesterKeys
// holding a key that could never verify an attestation, an attester
// with no issuer, or a kid naming two different keys of one attester,
// rather than answering invalid_client at the first attestation; it
// accepts a well-formed one, including one listing the same key twice.
func TestNewValidatesStaticAttesterKeys(t *testing.T) {
	good, other := generateKey(t), generateKey(t)
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	offCurve := &ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(1), Y: big.NewInt(1)}
	key := func(kid string, alg fapi.SignatureAlgorithm, pub any) keys.VerificationKey {
		return keys.VerificationKey{KeyID: kid, Algorithm: alg, PublicKey: pub}
	}
	cases := map[string]struct {
		keys    keys.StaticAttesterKeys
		wantErr string
	}{
		"well formed":                 {keys.StaticAttesterKeys{testAttesterIssuer: {key("a", fapi.ES256, &good.PublicKey), key("b", fapi.EdDSA, edPub)}}, ""},
		"same key listed twice":       {keys.StaticAttesterKeys{testAttesterIssuer: {key("a", fapi.ES256, &good.PublicKey), key("a", fapi.ES256, &good.PublicKey)}}, ""},
		"kid shared across attesters": {keys.StaticAttesterKeys{testAttesterIssuer: {key("a", fapi.ES256, &good.PublicKey)}, "https://other.example.com": {key("a", fapi.ES256, &other.PublicKey)}}, ""},
		"nil key":                     {keys.StaticAttesterKeys{testAttesterIssuer: {key("a", fapi.ES256, nil)}}, `key 0 (kid "a")`},
		"private key":                 {keys.StaticAttesterKeys{testAttesterIssuer: {key("a", fapi.ES256, good)}}, "*ecdsa.PrivateKey"},
		"ed25519 private key":         {keys.StaticAttesterKeys{testAttesterIssuer: {key("a", fapi.EdDSA, edPriv)}}, "ed25519.PrivateKey"},
		"wrong type for algorithm":    {keys.StaticAttesterKeys{testAttesterIssuer: {key("a", fapi.PS256, &good.PublicKey)}}, "PS256 requires an RSA public key"},
		"point off the curve":         {keys.StaticAttesterKeys{testAttesterIssuer: {key("a", fapi.ES256, offCurve)}}, "point on curve P-256"},
		"no algorithm":                {keys.StaticAttesterKeys{testAttesterIssuer: {key("a", 0, &good.PublicKey)}}, "unsupported algorithm"},
		"no issuer":                   {keys.StaticAttesterKeys{"": {key("a", fapi.ES256, &good.PublicKey)}}, "an attester has no issuer"},
		"kid naming two keys":         {keys.StaticAttesterKeys{testAttesterIssuer: {key("a", fapi.ES256, &good.PublicKey), key("a", fapi.ES256, &other.PublicKey)}}, `keys 0 and 1 share kid "a"`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			for _, source := range []keys.AttesterKeySource{tc.keys, &tc.keys} {
				checkNewWithAttesterKeys(t, source, tc.wantErr)
			}
		})
	}
}

// checkNewWithAttesterKeys builds a server whose attester keys are
// source, wanting New to fail with wantErr in its error, or succeed
// when wantErr is empty.
func checkNewWithAttesterKeys(t *testing.T, source keys.AttesterKeySource, wantErr string) {
	t.Helper()
	deps := validDependencies()
	deps.AttesterTrust = server.RegisteredAttesterKeys{Keys: source}
	_, err := server.New(validAttestationConfig(t), deps)
	switch {
	case wantErr == "" && err != nil:
		t.Fatalf("New(%T) = %v, want success", source, err)
	case wantErr != "" && (err == nil || !strings.Contains(err.Error(), wantErr)):
		t.Fatalf("New(%T) = %v, want an error containing %q", source, err, wantErr)
	}
}

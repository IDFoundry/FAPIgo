package server

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	fapi "github.com/idfoundry/fapigo"
)

// TestKeyFitsAlgorithm: an attester certificate's key must be the kind
// the client's attestation algorithm signs with, for each of ES256,
// PS256 and EdDSA, so a certificate for the wrong key type is refused
// before signature verification.
func TestKeyFitsAlgorithm(t *testing.T) {
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]crypto.PublicKey{
		"P-256": &p256.PublicKey, "P-384": &p384.PublicKey, "RSA": &rsaKey.PublicKey, "Ed25519": edPub,
	}
	fits := map[fapi.SignatureAlgorithm]string{fapi.ES256: "P-256", fapi.PS256: "RSA", fapi.EdDSA: "Ed25519"}
	for alg, want := range fits {
		for name, pub := range keys {
			if got := keyFitsAlgorithm(pub, alg); got != (name == want) {
				t.Errorf("keyFitsAlgorithm(%s key, %s) = %v, want %v", name, alg, got, name == want)
			}
		}
	}
}

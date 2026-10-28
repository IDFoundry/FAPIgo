package keys_test

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
)

func TestStaticClientKeysContract(t *testing.T) {
	keys.TestClientKeySourceContract(t, func(t *testing.T, clients map[fapi.ClientID][]byte) keys.ClientKeySource {
		material := make(map[fapi.ClientID]keys.ClientKeyMaterial, len(clients))
		for id, doc := range clients {
			material[id] = keys.ClientKeyMaterial{JWKS: doc}
		}
		src, err := keys.NewStaticClientKeys(material)
		if err != nil {
			t.Fatalf("NewStaticClientKeys: %v", err)
		}
		return src
	})
}

func newP256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return k
}

// TestStaticClientKeysServesKeysGivenDirectly: keys given as
// crypto.PublicKeys resolve per client, by algorithm and kid, and an
// unknown client is an error.
func TestStaticClientKeysServesKeysGivenDirectly(t *testing.T) {
	a, b := newP256(t), newP256(t)
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	src, err := keys.NewStaticClientKeys(map[fapi.ClientID]keys.ClientKeyMaterial{
		"a":    {VerificationKeys: []keys.VerificationKey{{KeyID: "k", Algorithm: fapi.ES256, PublicKey: &a.PublicKey}, {KeyID: "ed", Algorithm: fapi.EdDSA, PublicKey: ed.Public()}}},
		"b":    {VerificationKeys: []keys.VerificationKey{{KeyID: "k", Algorithm: fapi.ES256, PublicKey: &b.PublicKey}}},
		"mtls": {},
	})
	if err != nil {
		t.Fatalf("NewStaticClientKeys: %v", err)
	}
	resolve := func(id fapi.ClientID, alg fapi.SignatureAlgorithm, kid string) ([]keys.VerificationKey, error) {
		set, err := src.ResolveVerificationKeys(context.Background(), keys.ClientKeyRequest{ClientID: id, Purpose: keys.ClientAssertionVerification, Algorithm: alg, KeyID: kid})
		return set.Keys, err
	}
	if got, err := resolve("b", fapi.ES256, "k"); err != nil || len(got) != 1 || !b.PublicKey.Equal(got[0].PublicKey) {
		t.Fatalf("b/k: got %+v, err %v; want b's own key", got, err)
	}
	if got, err := resolve("a", fapi.EdDSA, ""); err != nil || len(got) != 1 || got[0].KeyID != "ed" {
		t.Fatalf("a/EdDSA: got %+v, err %v", got, err)
	}
	if got, err := resolve("mtls", fapi.ES256, ""); err != nil || len(got) != 0 {
		t.Fatalf("client with no keys: got %+v, err %v; want an empty set", got, err)
	}
	if _, err := resolve("c", fapi.ES256, "k"); err == nil {
		t.Fatalf("unknown client: no error")
	}
	if !src.Capabilities().LiveFetchHardened {
		t.Fatalf("StaticClientKeys fetches nothing, so should declare LiveFetchHardened")
	}
}

func TestStaticClientKeysResolvesEncryptionKeys(t *testing.T) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	src, err := keys.NewStaticClientKeys(map[fapi.ClientID]keys.ClientKeyMaterial{
		"a": {EncryptionKeys: []keys.ClientEncryptionKey{{KeyID: "enc", Algorithm: fapi.ECDHESA256KW, PublicKey: priv.PublicKey()}}},
		"b": {},
	})
	if err != nil {
		t.Fatalf("NewStaticClientKeys: %v", err)
	}
	var _ keys.ClientEncryptionKeySource = src
	resolve := func(id fapi.ClientID, alg fapi.KeyManagementAlgorithm) ([]keys.ClientEncryptionKey, error) {
		set, err := src.ResolveEncryptionKeys(context.Background(), keys.ClientEncryptionKeyRequest{ClientID: id, Purpose: keys.IDTokenEncryption, Algorithm: alg})
		return set.Keys, err
	}
	if got, err := resolve("a", fapi.ECDHESA256KW); err != nil || len(got) != 1 || got[0].KeyID != "enc" {
		t.Fatalf("a: got %+v, err %v", got, err)
	}
	if got, err := resolve("a", fapi.RSAOAEP256); err != nil || len(got) != 0 {
		t.Fatalf("a, other algorithm: got %+v, err %v; want none", got, err)
	}
	if got, err := resolve("b", fapi.ECDHESA256KW); err != nil || len(got) != 0 {
		t.Fatalf("b: got %+v, err %v; want none of a's keys", got, err)
	}
	if _, err := resolve("c", fapi.ECDHESA256KW); err == nil {
		t.Fatalf("unknown client: no error")
	}
}

// rsaPublicKey is an RSA public key of bits bits with exponent e — not
// a usable key pair, which these checks don't need.
func rsaPublicKey(bits, e int) *rsa.PublicKey {
	n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	return &rsa.PublicKey{N: n.Add(n, big.NewInt(1)), E: e}
}

// TestNewStaticClientKeysValidatesKeys: every key is validated once, at
// construction, to the limits of a key a caller supplies.
func TestNewStaticClientKeysValidatesKeys(t *testing.T) {
	ec := newP256(t)
	offCurve := &ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(1), Y: big.NewInt(1)}
	ecdhKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	cases := []struct {
		name    string
		clients map[fapi.ClientID]keys.ClientKeyMaterial
		want    string
	}{
		{"empty client ID", map[fapi.ClientID]keys.ClientKeyMaterial{"": {}}, "no client ID"},
		{"malformed jwks", map[fapi.ClientID]keys.ClientKeyMaterial{"a": {JWKS: []byte(`{"keys":`)}}, "jwks"},
		{"jwks with no usable key", map[fapi.ClientID]keys.ClientKeyMaterial{"a": {JWKS: []byte(`{"keys":[{"kty":"oct","k":"AAAA"}]}`)}}, "no usable keys"},
		{"missing algorithm", verification(keys.VerificationKey{PublicKey: &ec.PublicKey}), "unsupported algorithm"},
		{"key type mismatch", verification(keys.VerificationKey{Algorithm: fapi.PS256, PublicKey: &ec.PublicKey}), "RSA public key"},
		{"point off the curve", verification(keys.VerificationKey{Algorithm: fapi.ES256, PublicKey: offCurve}), "ecdsa public key"},
		{"RSA key under 2048 bits", verification(keys.VerificationKey{Algorithm: fapi.PS256, PublicKey: rsaPublicKey(1024, 65537)}), "at least 2048"},
		{"RSA key over 4096 bits", verification(keys.VerificationKey{Algorithm: fapi.PS256, PublicKey: rsaPublicKey(8192, 65537)}), "too large"},
		{"RSA exponent other than 65537", verification(keys.VerificationKey{Algorithm: fapi.PS256, PublicKey: rsaPublicKey(2048, 3)}), "exponent"},
		{"encryption key over 4096 bits", encryption(keys.ClientEncryptionKey{Algorithm: fapi.RSAOAEP256, PublicKey: rsaPublicKey(8192, 65537)}), "too large"},
		{"encryption key type mismatch", encryption(keys.ClientEncryptionKey{Algorithm: fapi.RSAOAEP256, PublicKey: ecdhKey.PublicKey()}), "RSA public key"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := keys.NewStaticClientKeys(c.clients)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want one mentioning %q", err, c.want)
			}
		})
	}
	if _, err := keys.NewStaticClientKeys(verification(keys.VerificationKey{Algorithm: fapi.PS256, PublicKey: rsaPublicKey(4096, 65537)})); err != nil {
		t.Fatalf("a 4096-bit RSA key: %v", err)
	}
}

func verification(k keys.VerificationKey) map[fapi.ClientID]keys.ClientKeyMaterial {
	return map[fapi.ClientID]keys.ClientKeyMaterial{"a": {VerificationKeys: []keys.VerificationKey{k}}}
}

func encryption(k keys.ClientEncryptionKey) map[fapi.ClientID]keys.ClientKeyMaterial {
	return map[fapi.ClientID]keys.ClientKeyMaterial{"a": {EncryptionKeys: []keys.ClientEncryptionKey{k}}}
}

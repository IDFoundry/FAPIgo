package jose

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"

	fapi "github.com/idfoundry/fapigo"
)

func encryptionJWK(t *testing.T, pub any, alg fapi.KeyManagementAlgorithm, kid string) JWK {
	t.Helper()
	jwk, err := NewEncryptionJWK(pub, alg)
	if err != nil {
		t.Fatalf("NewEncryptionJWK: %v", err)
	}
	return jwk.WithKeyID(kid)
}

func testRSAKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestParseEncryptionJWKSet(t *testing.T) {
	rsaKey := testRSAKey(t, 2048)
	ecKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sigKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sigJWK, err := NewJWK(&sigKey.PublicKey, fapi.ES256)
	if err != nil {
		t.Fatal(err)
	}
	// Too small for RSA-OAEP-256: NewEncryptionJWK refuses to build one.
	smallRSA := JWK{pub: &testRSAKey(t, 1024).PublicKey, use: jwkUseEncryption, encAlg: fapi.RSAOAEP256}.WithKeyID("small")

	body := jwkSetBody(t,
		// This package's own encryption JWKs: "use":"enc" and "alg".
		rawKeySetEntry(t, encryptionJWK(t, &rsaKey.PublicKey, fapi.RSAOAEP256, "rsa-enc"), nil),
		// "use":"enc" with no "alg": the key type decides.
		rawKeySetEntry(t, encryptionJWK(t, ecKey.PublicKey(), fapi.ECDHESA256KW, "ec-enc"), map[string]any{"alg": nil}),
		// An explicit key management "alg", with no "use".
		rawKeySetEntry(t, encryptionJWK(t, &rsaKey.PublicKey, fapi.RSAOAEP256, "rsa-alg"), map[string]any{"use": nil, "alg": "RSA-OAEP-256"}),
		// Not encryption keys: a signature key, an RSA key with neither
		// "use" nor "alg", one marked "use":"sig", an unsupported "alg",
		// a key too small for RSA-OAEP-256, and private key material.
		rawKeySetEntry(t, sigJWK.WithKeyID("sig"), nil),
		rawKeySetEntry(t, encryptionJWK(t, &rsaKey.PublicKey, fapi.RSAOAEP256, "bare"), map[string]any{"use": nil, "alg": nil}),
		rawKeySetEntry(t, encryptionJWK(t, &rsaKey.PublicKey, fapi.RSAOAEP256, "marked-sig"), map[string]any{"use": "sig", "alg": nil}),
		rawKeySetEntry(t, encryptionJWK(t, &rsaKey.PublicKey, fapi.RSAOAEP256, "rsa-oaep"), map[string]any{"alg": "RSA-OAEP"}),
		rawKeySetEntry(t, smallRSA, nil),
		rawKeySetEntry(t, encryptionJWK(t, &rsaKey.PublicKey, fapi.RSAOAEP256, "private"), map[string]any{"d": "AQAB"}),
	)
	got, err := ParseEncryptionJWKSet(body)
	if err != nil {
		t.Fatalf("ParseEncryptionJWKSet: %v", err)
	}
	want := map[string]fapi.KeyManagementAlgorithm{"rsa-enc": fapi.RSAOAEP256, "ec-enc": fapi.ECDHESA256KW, "rsa-alg": fapi.RSAOAEP256}
	if len(got) != len(want) {
		t.Fatalf("got %d keys %v, want %d", len(got), got, len(want))
	}
	for _, k := range got {
		if alg, ok := want[k.KeyID]; !ok || k.Algorithm != alg {
			t.Errorf("key %q: algorithm %v, want %v (wanted: %v)", k.KeyID, k.Algorithm, alg, ok)
		}
		if k.KeyID == "ec-enc" {
			if _, ok := k.PublicKey.(*ecdh.PublicKey); !ok {
				t.Errorf("ec-enc public key is %T, want *ecdh.PublicKey", k.PublicKey)
			}
		}
	}
}

// TestParseJWKSetSkipsEncryptionKeys covers RFC 7517 §4.2: an RSA key
// marked "use":"enc" with no "alg" — as a JWK Set from elsewhere may
// publish one — isn't a PS256 signature verification key, though its
// key type alone would make it one.
func TestParseJWKSetSkipsEncryptionKeys(t *testing.T) {
	rsaKey := testRSAKey(t, 2048)
	body := jwkSetBody(t, rawKeySetEntry(t, encryptionJWK(t, &rsaKey.PublicKey, fapi.RSAOAEP256, "rsa-enc"), map[string]any{"alg": nil}))
	var check map[string][]map[string]any
	_ = json.Unmarshal(body, &check)
	if entry := check["keys"][0]; entry["use"] != "enc" || entry["alg"] != nil {
		t.Fatalf("fixture = %v, want use enc and no alg", entry)
	}
	got, err := ParseJWKSet(body)
	if err != nil {
		t.Fatalf("ParseJWKSet: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("ParseJWKSet returned %d keys from an encryption-only set, want 0: %v", len(got), got)
	}
}

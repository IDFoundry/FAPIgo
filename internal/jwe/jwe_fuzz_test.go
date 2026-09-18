package jwe

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	fapi "github.com/idfoundry/fapigo"
)

// FuzzDecrypt exercises Decrypt against arbitrary compact-serialization
// strings — a JWE arrives as a client-supplied encrypted request object
// or, on the client side, an encrypted ID token/UserInfo response, in
// every case parsed (segment split, four separate base64url decodes,
// header parsing) before any authentication happens. Runs every fuzzed
// input against all four algorithm/content-encryption combinations this
// package supports, each under a real generated key, so the fuzzer
// reaches UnwrapCEK (RSA-OAEP and ECDH-ES+A256KW) and openContent
// (AES-GCM and AES-CBC-HMAC) — not just the initial segment/base64/
// header parsing every combination shares. Only checks for panics/
// hangs: almost every mutated input is expected to fail decryption or
// authentication, so there is no useful correctness oracle beyond
// "never crashes, never loops".
func FuzzDecrypt(f *testing.F) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatalf("generate rsa key: %v", err)
	}
	ecdhKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		f.Fatalf("generate ecdh key: %v", err)
	}

	type combo struct {
		alg fapi.KeyManagementAlgorithm
		enc fapi.ContentEncryptionAlgorithm
		key any // the recipient's own private key, for Decrypt
		pub any // the matching public key, for building seeds via Encrypt
	}
	combos := []combo{
		{fapi.RSAOAEP256, fapi.A256GCM, rsaKey, &rsaKey.PublicKey},
		{fapi.RSAOAEP256, fapi.A256CBCHS512, rsaKey, &rsaKey.PublicKey},
		{fapi.ECDHESA256KW, fapi.A256GCM, ecdhKey, ecdhKey.PublicKey()},
		{fapi.ECDHESA256KW, fapi.A256CBCHS512, ecdhKey, ecdhKey.PublicKey()},
	}

	for _, c := range combos {
		token, err := Encrypt(EncryptRequest{
			Algorithm: c.alg, Encryption: c.enc, RecipientKey: c.pub,
			Plaintext: []byte(`{"hello":"world"}`),
		})
		if err != nil {
			f.Fatalf("Encrypt(%v/%v): %v", c.alg, c.enc, err)
		}
		f.Add(token)
	}
	f.Add("")
	f.Add(".")
	f.Add("a.b.c.d")
	f.Add("a.b.c.d.e")
	f.Add("a.b.c..e")

	f.Fuzz(func(t *testing.T, compact string) {
		for _, c := range combos {
			_, _ = Decrypt(context.Background(), DecryptRequest{
				Algorithm: c.alg, Encryption: c.enc, RecipientKey: c.key, Compact: compact,
			})
		}
	})
}

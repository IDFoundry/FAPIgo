package jwe

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
)

// FuzzEncryptDecryptTamper checks the property FuzzDecrypt deliberately
// doesn't: that Encrypt/Decrypt round-trip exactly, and that any
// single-byte change anywhere in a genuinely encrypted token —
// header, encrypted key, IV, ciphertext, or authentication tag — always
// causes Decrypt to fail. FuzzDecrypt fuzzes the compact string
// directly against a fixed valid structure and only checks for panics,
// since almost every mutation it tries fails to parse or authenticate
// for uninteresting reasons; this target instead starts from a real
// Encrypt output and mutates one already-decoded segment byte at a
// time, so a tampered input that still reaches Decrypt's authentication
// step is testing a genuine semantic difference. This is the property
// that actually matters for this package's Vaudenay-padding-oracle
// defense (openCBCHMAC verifies the HMAC tag before ever running
// CBC-decrypt/unpad) — under both content-encryption families, not
// just CBC-HMAC's own unit tests.
func FuzzEncryptDecryptTamper(f *testing.F) {
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
		key any // recipient's own private key, for Decrypt
		pub any // matching public key, for Encrypt
	}
	combos := []combo{
		{fapi.RSAOAEP256, fapi.A256GCM, rsaKey, &rsaKey.PublicKey},
		{fapi.RSAOAEP256, fapi.A256CBCHS512, rsaKey, &rsaKey.PublicKey},
		{fapi.ECDHESA256KW, fapi.A256GCM, ecdhKey, ecdhKey.PublicKey()},
		{fapi.ECDHESA256KW, fapi.A256CBCHS512, ecdhKey, ecdhKey.PublicKey()},
	}

	f.Add([]byte(`{"hello":"world"}`), 0, uint8(0), 0, uint8(0x01))
	f.Add([]byte(""), 1, uint8(2), 0, uint8(0xFF))
	f.Add([]byte(`{"a":1,"b":2}`), 3, uint8(4), 5, uint8(0x80))

	f.Fuzz(func(t *testing.T, plaintext []byte, comboIdx int, segment uint8, bytePos int, mask uint8) {
		c := combos[((comboIdx%len(combos))+len(combos))%len(combos)]

		token, err := Encrypt(EncryptRequest{
			Algorithm: c.alg, Encryption: c.enc, RecipientKey: c.pub,
			Plaintext: plaintext,
		})
		if err != nil {
			t.Fatalf("Encrypt(%v/%v): %v", c.alg, c.enc, err)
		}

		result, err := Decrypt(context.Background(), DecryptRequest{
			Algorithm: c.alg, Encryption: c.enc, RecipientKey: c.key, Compact: token,
		})
		if err != nil {
			t.Fatalf("Decrypt(untampered, %v/%v): %v", c.alg, c.enc, err)
		}
		if !bytes.Equal(result.Plaintext, plaintext) {
			t.Fatalf("round-trip plaintext mismatch: got %q, want %q", result.Plaintext, plaintext)
		}

		parts := strings.Split(token, ".")
		if len(parts) != 5 {
			t.Fatalf("own Encrypt output did not split into 5 segments: %q", token)
		}
		segIdx := int(segment) % 5
		raw, err := base64.RawURLEncoding.DecodeString(parts[segIdx])
		if err != nil || len(raw) == 0 {
			return
		}
		if mask == 0 {
			mask = 1
		}
		pos := ((bytePos % len(raw)) + len(raw)) % len(raw)
		raw[pos] ^= mask
		parts[segIdx] = base64.RawURLEncoding.EncodeToString(raw)
		tampered := strings.Join(parts, ".")

		if _, err := Decrypt(context.Background(), DecryptRequest{
			Algorithm: c.alg, Encryption: c.enc, RecipientKey: c.key, Compact: tampered,
		}); err == nil {
			t.Fatalf("Decrypt succeeded after single-byte tamper: %v/%v segment=%d pos=%d mask=%#x original=%q tampered=%q",
				c.alg, c.enc, segIdx, pos, mask, token, tampered)
		}
	})
}

package jwe

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
)

// encryptForLengthTest returns a valid compact JWE for enc, encrypted
// to the returned recipient key.
func encryptForLengthTest(t *testing.T, enc fapi.ContentEncryptionAlgorithm) (*rsa.PrivateKey, []string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := Encrypt(EncryptRequest{
		Algorithm: fapi.RSAOAEP256, Encryption: enc, RecipientKey: &key.PublicKey, Plaintext: []byte(`{"sub":"x"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	return key, strings.Split(compact, ".")
}

func decryptForLengthTest(t *testing.T, key *rsa.PrivateKey, enc fapi.ContentEncryptionAlgorithm, parts []string) (err error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Decrypt panicked: %v", r)
		}
	}()
	_, err = Decrypt(context.Background(), DecryptRequest{
		Algorithm: fapi.RSAOAEP256, Encryption: enc, RecipientKey: key, Compact: strings.Join(parts, "."),
	})
	return err
}

// TestDecryptRejectsWrongLengths covers an IV or tag of the wrong length
// for the content encryption algorithm, in a JWE whose key wrap is
// otherwise valid. Before these were checked, a wrong-length A256GCM IV
// reached cipher.AEAD.Open and panicked the decrypting process: a JWE
// anyone holding the recipient's public key could build.
func TestDecryptRejectsWrongLengths(t *testing.T) {
	b64 := base64.RawURLEncoding.EncodeToString
	for name, tc := range map[string]struct {
		enc     fapi.ContentEncryptionAlgorithm
		segment int
		value   []byte
	}{
		"A256GCM IV of 1 byte":          {fapi.A256GCM, 2, []byte{1}},
		"A256GCM IV of 16 bytes":        {fapi.A256GCM, 2, make([]byte, 16)},
		"A256GCM tag of 15 bytes":       {fapi.A256GCM, 4, make([]byte, 15)},
		"A256GCM tag of 17 bytes":       {fapi.A256GCM, 4, make([]byte, 17)},
		"A256CBC-HS512 IV of 12 bytes":  {fapi.A256CBCHS512, 2, make([]byte, 12)},
		"A256CBC-HS512 tag of 16 bytes": {fapi.A256CBCHS512, 4, make([]byte, 16)},
	} {
		t.Run(name, func(t *testing.T) {
			key, parts := encryptForLengthTest(t, tc.enc)
			parts[tc.segment] = b64(tc.value)
			if err := decryptForLengthTest(t, key, tc.enc, parts); !errors.Is(err, ErrMalformed) {
				t.Fatalf("Decrypt = %v, want ErrMalformed", err)
			}
		})
	}
}

// TestDecryptRejectsWrongCEKLength covers a sender that wraps a 16-byte
// key under A256GCM: AES would accept it as AES-128, silently weakening
// the encryption the header names.
func TestDecryptRejectsWrongCEKLength(t *testing.T) {
	key, parts := encryptForLengthTest(t, fapi.A256GCM)
	cek := make([]byte, 16)
	if _, err := rand.Read(cek); err != nil {
		t.Fatal(err)
	}
	wrapped, _, err := wrapCEKRSAOAEP256(&key.PublicKey, cek, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	iv := make([]byte, gcmNonceSize)
	sealed := gcm.Seal(nil, iv, []byte(`{"sub":"x"}`), []byte(parts[0]))
	b64 := base64.RawURLEncoding.EncodeToString
	parts[1], parts[2] = b64(wrapped), b64(iv)
	parts[3], parts[4] = b64(sealed[:len(sealed)-16]), b64(sealed[len(sealed)-16:])
	if err := decryptForLengthTest(t, key, fapi.A256GCM, parts); !errors.Is(err, ErrMalformed) {
		t.Fatalf("Decrypt(16-byte CEK under A256GCM) = %v, want ErrMalformed", err)
	}
}

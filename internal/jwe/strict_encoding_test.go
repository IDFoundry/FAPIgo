package jwe

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
)

// TestDecryptRefusesNonCanonicalEncodings: the tag, IV and encrypted
// key aren't covered by the AAD as strings, so a lenient decoder would
// decrypt several different compact strings to the same plaintext.
func TestDecryptRefusesNonCanonicalEncodings(t *testing.T) {
	priv := generateRSAKey(t)
	compact, err := Encrypt(EncryptRequest{
		Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256GCM,
		RecipientKey: &priv.PublicKey, Plaintext: []byte("plaintext"),
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	decrypt := func(c string) error {
		_, err := Decrypt(context.Background(), DecryptRequest{
			Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256GCM,
			RecipientKey: priv, Compact: c,
		})
		return err
	}
	if err := decrypt(compact); err != nil {
		t.Fatalf("Decrypt(canonical): %v", err)
	}
	parts := strings.Split(compact, ".")
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	tag := parts[4]
	i := strings.IndexByte(alphabet, tag[len(tag)-1])
	malleatedTag := tag[:len(tag)-1] + string(alphabet[i|1])
	if lenient, err := base64.RawURLEncoding.DecodeString(malleatedTag); err != nil || len(lenient) != 16 {
		t.Fatalf("premise: lenient decode of the malleated tag = %d bytes, %v", len(lenient), err)
	}
	with := func(i int, seg string) string {
		p := append([]string{}, parts...)
		p[i] = seg
		return strings.Join(p, ".")
	}
	for name, c := range map[string]string{
		"tag trailing bits":             with(4, malleatedTag),
		"iv line feed":                  with(2, parts[2][:4]+"\n"+parts[2][4:]),
		"encrypted key carriage return": with(1, parts[1][:8]+"\r"+parts[1][8:]),
	} {
		t.Run(name, func(t *testing.T) {
			if err := decrypt(c); !errors.Is(err, ErrMalformed) {
				t.Fatalf("Decrypt(%s) = %v, want ErrMalformed", name, err)
			}
		})
	}
}

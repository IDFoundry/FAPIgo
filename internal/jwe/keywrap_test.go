package jwe

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

// RFC 3394 §4.1 "Wrap 128 bits of Key Data with a 128-bit KEK" — the
// spec's own worked example, reproduced verbatim so this implementation
// is checked against a known-answer test, not just its own round trip.
func TestAESKeyWrapRFC3394KnownAnswer(t *testing.T) {
	kek := mustHex(t, "000102030405060708090A0B0C0D0E0F")
	keyData := mustHex(t, "00112233445566778899AABBCCDDEEFF")
	wantWrapped := mustHex(t, "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")

	got, err := aesKeyWrap(kek, keyData)
	if err != nil {
		t.Fatalf("aesKeyWrap: %v", err)
	}
	if !bytes.Equal(got, wantWrapped) {
		t.Fatalf("aesKeyWrap(%x, %x) = %x, want %x", kek, keyData, got, wantWrapped)
	}

	unwrapped, err := aesKeyUnwrap(kek, got)
	if err != nil {
		t.Fatalf("aesKeyUnwrap: %v", err)
	}
	if !bytes.Equal(unwrapped, keyData) {
		t.Fatalf("aesKeyUnwrap round trip = %x, want %x", unwrapped, keyData)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q): %v", s, err)
	}
	return b
}

func TestAESKeyWrapRoundTrip256(t *testing.T) {
	kek := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		t.Fatalf("generate kek: %v", err)
	}
	cek := make([]byte, 32)
	if _, err := rand.Read(cek); err != nil {
		t.Fatalf("generate cek: %v", err)
	}

	wrapped, err := aesKeyWrap(kek, cek)
	if err != nil {
		t.Fatalf("aesKeyWrap: %v", err)
	}
	if len(wrapped) != len(cek)+8 {
		t.Fatalf("len(wrapped) = %d, want %d", len(wrapped), len(cek)+8)
	}
	unwrapped, err := aesKeyUnwrap(kek, wrapped)
	if err != nil {
		t.Fatalf("aesKeyUnwrap: %v", err)
	}
	if !bytes.Equal(unwrapped, cek) {
		t.Fatalf("round trip = %x, want %x", unwrapped, cek)
	}
}

func TestAESKeyUnwrapRejectsWrongKEK(t *testing.T) {
	kek := make([]byte, 32)
	wrongKEK := make([]byte, 32)
	wrongKEK[0] = 1 // ensure it differs from the (zero) kek
	cek := make([]byte, 32)
	for i := range cek {
		cek[i] = byte(i)
	}

	wrapped, err := aesKeyWrap(kek, cek)
	if err != nil {
		t.Fatalf("aesKeyWrap: %v", err)
	}
	if _, err := aesKeyUnwrap(wrongKEK, wrapped); err == nil {
		t.Fatalf("aesKeyUnwrap(wrong kek) = nil error, want error")
	}
}

func TestAESKeyUnwrapRejectsTamperedCiphertext(t *testing.T) {
	kek := make([]byte, 32)
	cek := make([]byte, 32)
	for i := range cek {
		cek[i] = byte(i)
	}
	wrapped, err := aesKeyWrap(kek, cek)
	if err != nil {
		t.Fatalf("aesKeyWrap: %v", err)
	}
	wrapped[len(wrapped)-1] ^= 0xFF
	if _, err := aesKeyUnwrap(kek, wrapped); err == nil {
		t.Fatalf("aesKeyUnwrap(tampered) = nil error, want error")
	}
}

func TestAESKeyWrapRejectsInvalidPlaintextLength(t *testing.T) {
	kek := make([]byte, 32)
	for _, n := range []int{0, 8, 15, 17} {
		if _, err := aesKeyWrap(kek, make([]byte, n)); err == nil {
			t.Fatalf("aesKeyWrap(plaintext len %d) = nil error, want error", n)
		}
	}
}

func TestAESKeyUnwrapRejectsInvalidCiphertextLength(t *testing.T) {
	kek := make([]byte, 32)
	for _, n := range []int{0, 16, 23, 25} {
		if _, err := aesKeyUnwrap(kek, make([]byte, n)); err == nil {
			t.Fatalf("aesKeyUnwrap(ciphertext len %d) = nil error, want error", n)
		}
	}
}

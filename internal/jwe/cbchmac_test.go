package jwe

import (
	"bytes"
	"testing"
)

// TestCBCHMACRFC7518AppendixB3KnownAnswer is the worked
// AEAD_AES_256_CBC_HMAC_SHA_512 example from RFC 7518 Appendix B.3
// (originally published in draft-mcgrew-aead-aes-cbc-hmac-sha2 §5.4,
// which RFC 7518 §5.2 adopted directly) — a fixed, publicly known
// input/output pair, not derived from this package's own code, so it
// can catch a self-consistent-but-non-interoperable bug that a
// round-trip-only test (encrypt then decrypt with the same code) could
// never see — e.g. swapping which half of K is MAC_KEY vs ENC_KEY:
// round-tripping would still pass even swapped, but every other JOSE
// implementation would fail to decrypt the result.
func TestCBCHMACRFC7518AppendixB3KnownAnswer(t *testing.T) {
	// K = MAC_KEY (initial 32 octets) || ENC_KEY (final 32 octets),
	// each simply 0x00..0x1f / 0x20..0x3f in the published example.
	k := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
	}
	iv := []byte{0x1a, 0xf3, 0x8c, 0x2d, 0xc2, 0xb9, 0x6f, 0xfd, 0xd8, 0x66, 0x94, 0x09, 0x23, 0x41, 0xbc, 0x04}
	// A = ASCII "The second principle of Auguste Kerckhoffs"
	aad := []byte{
		0x54, 0x68, 0x65, 0x20, 0x73, 0x65, 0x63, 0x6f, 0x6e, 0x64, 0x20, 0x70, 0x72, 0x69, 0x6e, 0x63,
		0x69, 0x70, 0x6c, 0x65, 0x20, 0x6f, 0x66, 0x20, 0x41, 0x75, 0x67, 0x75, 0x73, 0x74, 0x65, 0x20,
		0x4b, 0x65, 0x72, 0x63, 0x6b, 0x68, 0x6f, 0x66, 0x66, 0x73,
	}
	// P = ASCII "A cipher system must not be required to be secret,
	// and it must be able to fall into the hands of the enemy without
	// inconvenience"
	plaintext := []byte{
		0x41, 0x20, 0x63, 0x69, 0x70, 0x68, 0x65, 0x72, 0x20, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x20,
		0x6d, 0x75, 0x73, 0x74, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x65, 0x71, 0x75,
		0x69, 0x72, 0x65, 0x64, 0x20, 0x74, 0x6f, 0x20, 0x62, 0x65, 0x20, 0x73, 0x65, 0x63, 0x72, 0x65,
		0x74, 0x2c, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x69, 0x74, 0x20, 0x6d, 0x75, 0x73, 0x74, 0x20, 0x62,
		0x65, 0x20, 0x61, 0x62, 0x6c, 0x65, 0x20, 0x74, 0x6f, 0x20, 0x66, 0x61, 0x6c, 0x6c, 0x20, 0x69,
		0x6e, 0x74, 0x6f, 0x20, 0x74, 0x68, 0x65, 0x20, 0x68, 0x61, 0x6e, 0x64, 0x73, 0x20, 0x6f, 0x66,
		0x20, 0x74, 0x68, 0x65, 0x20, 0x65, 0x6e, 0x65, 0x6d, 0x79, 0x20, 0x77, 0x69, 0x74, 0x68, 0x6f,
		0x75, 0x74, 0x20, 0x69, 0x6e, 0x63, 0x6f, 0x6e, 0x76, 0x65, 0x6e, 0x69, 0x65, 0x6e, 0x63, 0x65,
	}
	wantCiphertext := []byte{
		0x4a, 0xff, 0xaa, 0xad, 0xb7, 0x8c, 0x31, 0xc5, 0xda, 0x4b, 0x1b, 0x59, 0x0d, 0x10, 0xff, 0xbd,
		0x3d, 0xd8, 0xd5, 0xd3, 0x02, 0x42, 0x35, 0x26, 0x91, 0x2d, 0xa0, 0x37, 0xec, 0xbc, 0xc7, 0xbd,
		0x82, 0x2c, 0x30, 0x1d, 0xd6, 0x7c, 0x37, 0x3b, 0xcc, 0xb5, 0x84, 0xad, 0x3e, 0x92, 0x79, 0xc2,
		0xe6, 0xd1, 0x2a, 0x13, 0x74, 0xb7, 0x7f, 0x07, 0x75, 0x53, 0xdf, 0x82, 0x94, 0x10, 0x44, 0x6b,
		0x36, 0xeb, 0xd9, 0x70, 0x66, 0x29, 0x6a, 0xe6, 0x42, 0x7e, 0xa7, 0x5c, 0x2e, 0x08, 0x46, 0xa1,
		0x1a, 0x09, 0xcc, 0xf5, 0x37, 0x0d, 0xc8, 0x0b, 0xfe, 0xcb, 0xad, 0x28, 0xc7, 0x3f, 0x09, 0xb3,
		0xa3, 0xb7, 0x5e, 0x66, 0x2a, 0x25, 0x94, 0x41, 0x0a, 0xe4, 0x96, 0xb2, 0xe2, 0xe6, 0x60, 0x9e,
		0x31, 0xe6, 0xe0, 0x2c, 0xc8, 0x37, 0xf0, 0x53, 0xd2, 0x1f, 0x37, 0xff, 0x4f, 0x51, 0x95, 0x0b,
		0xbe, 0x26, 0x38, 0xd0, 0x9d, 0xd7, 0xa4, 0x93, 0x09, 0x30, 0x80, 0x6d, 0x07, 0x03, 0xb1, 0xf6,
	}
	wantTag := []byte{
		0x4d, 0xd3, 0xb4, 0xc0, 0x88, 0xa7, 0xf4, 0x5c, 0x21, 0x68, 0x39, 0x64, 0x5b, 0x20, 0x12, 0xbf,
		0x2e, 0x62, 0x69, 0xa8, 0xc5, 0x6a, 0x81, 0x6d, 0xbc, 0x1b, 0x26, 0x77, 0x61, 0x95, 0x5b, 0xc5,
	}

	gotCiphertext, gotTag, err := sealCBCHMAC(k, iv, plaintext, aad)
	if err != nil {
		t.Fatalf("sealCBCHMAC: %v", err)
	}
	if !bytes.Equal(gotCiphertext, wantCiphertext) {
		t.Fatalf("sealCBCHMAC ciphertext = %x, want %x", gotCiphertext, wantCiphertext)
	}
	if !bytes.Equal(gotTag, wantTag) {
		t.Fatalf("sealCBCHMAC tag = %x, want %x", gotTag, wantTag)
	}

	gotPlaintext, err := openCBCHMAC(k, iv, wantCiphertext, wantTag, aad)
	if err != nil {
		t.Fatalf("openCBCHMAC: %v", err)
	}
	if !bytes.Equal(gotPlaintext, plaintext) {
		t.Fatalf("openCBCHMAC plaintext = %x, want %x", gotPlaintext, plaintext)
	}
}

func TestCBCHMACRoundTrip(t *testing.T) {
	cek := make([]byte, cekSizeA256CBCHS512)
	for i := range cek {
		cek[i] = byte(i)
	}
	iv := make([]byte, cbcIVSize)
	for i := range iv {
		iv[i] = byte(0xa0 + i)
	}
	aad := []byte("protected-header")

	for _, plaintext := range [][]byte{
		[]byte("hello, world"),
		[]byte(""),
		bytes.Repeat([]byte{0x42}, 16),  // exactly one block
		bytes.Repeat([]byte{0x42}, 15),  // one byte short of a block
		bytes.Repeat([]byte{0x42}, 100), // spans several blocks
	} {
		ciphertext, tag, err := sealCBCHMAC(cek, iv, plaintext, aad)
		if err != nil {
			t.Fatalf("sealCBCHMAC(%d-byte plaintext): %v", len(plaintext), err)
		}
		got, err := openCBCHMAC(cek, iv, ciphertext, tag, aad)
		if err != nil {
			t.Fatalf("openCBCHMAC(%d-byte plaintext): %v", len(plaintext), err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("round trip(%d-byte plaintext) = %x, want %x", len(plaintext), got, plaintext)
		}
	}
}

func TestOpenCBCHMACRejectsTamperedTag(t *testing.T) {
	cek := make([]byte, cekSizeA256CBCHS512)
	iv := make([]byte, cbcIVSize)
	aad := []byte("aad")
	ciphertext, tag, err := sealCBCHMAC(cek, iv, []byte("plaintext"), aad)
	if err != nil {
		t.Fatalf("sealCBCHMAC: %v", err)
	}
	tampered := bytes.Clone(tag)
	tampered[0] ^= 0xff

	if _, err := openCBCHMAC(cek, iv, ciphertext, tampered, aad); err == nil {
		t.Fatalf("openCBCHMAC(tampered tag) = nil error, want error")
	}
}

func TestOpenCBCHMACRejectsTamperedCiphertext(t *testing.T) {
	cek := make([]byte, cekSizeA256CBCHS512)
	iv := make([]byte, cbcIVSize)
	aad := []byte("aad")
	ciphertext, tag, err := sealCBCHMAC(cek, iv, []byte("plaintext-longer-than-one-block!!"), aad)
	if err != nil {
		t.Fatalf("sealCBCHMAC: %v", err)
	}
	tampered := bytes.Clone(ciphertext)
	tampered[0] ^= 0xff

	if _, err := openCBCHMAC(cek, iv, tampered, tag, aad); err == nil {
		t.Fatalf("openCBCHMAC(tampered ciphertext) = nil error, want error")
	}
}

func TestOpenCBCHMACRejectsTamperedAAD(t *testing.T) {
	cek := make([]byte, cekSizeA256CBCHS512)
	iv := make([]byte, cbcIVSize)
	ciphertext, tag, err := sealCBCHMAC(cek, iv, []byte("plaintext"), []byte("original-aad"))
	if err != nil {
		t.Fatalf("sealCBCHMAC: %v", err)
	}

	if _, err := openCBCHMAC(cek, iv, ciphertext, tag, []byte("different-aad")); err == nil {
		t.Fatalf("openCBCHMAC(tampered aad) = nil error, want error")
	}
}

func TestOpenCBCHMACRejectsWrongKey(t *testing.T) {
	cek := make([]byte, cekSizeA256CBCHS512)
	iv := make([]byte, cbcIVSize)
	aad := []byte("aad")
	ciphertext, tag, err := sealCBCHMAC(cek, iv, []byte("plaintext"), aad)
	if err != nil {
		t.Fatalf("sealCBCHMAC: %v", err)
	}

	wrongCEK := make([]byte, cekSizeA256CBCHS512)
	wrongCEK[0] = 0x01
	if _, err := openCBCHMAC(wrongCEK, iv, ciphertext, tag, aad); err == nil {
		t.Fatalf("openCBCHMAC(wrong key) = nil error, want error")
	}
}

func TestSealCBCHMACRejectsWrongCEKSize(t *testing.T) {
	if _, _, err := sealCBCHMAC(make([]byte, 32), make([]byte, cbcIVSize), []byte("x"), nil); err == nil {
		t.Fatalf("sealCBCHMAC(32-byte cek) = nil error, want error")
	}
}

func TestOpenCBCHMACRejectsWrongCEKSize(t *testing.T) {
	if _, err := openCBCHMAC(make([]byte, 32), make([]byte, cbcIVSize), []byte("x"), make([]byte, cbcHMACTagSize), nil); err == nil {
		t.Fatalf("openCBCHMAC(32-byte cek) = nil error, want error")
	}
}

func TestOpenCBCHMACRejectsEmptyCiphertext(t *testing.T) {
	cek := make([]byte, cekSizeA256CBCHS512)
	iv := make([]byte, cbcIVSize)
	aad := []byte("aad")
	// A tag matching an empty ciphertext, so this exercises the
	// explicit empty-ciphertext rejection in openCBCHMAC, not the tag
	// check ahead of it.
	tag := cbcHMACTag(cek[:32], aad, iv, nil)
	if _, err := openCBCHMAC(cek, iv, nil, tag, aad); err == nil {
		t.Fatalf("openCBCHMAC(empty ciphertext) = nil error, want error")
	}
}

func TestPKCS7PadUnpadRoundTrip(t *testing.T) {
	for length := 0; length < 40; length++ {
		data := bytes.Repeat([]byte{0x7a}, length)
		padded, err := pkcs7Pad(data, 16)
		if err != nil {
			t.Fatalf("pkcs7Pad(%d bytes): %v", length, err)
		}
		if len(padded)%16 != 0 {
			t.Fatalf("pkcs7Pad(%d bytes) length %d, not a multiple of 16", length, len(padded))
		}
		if len(padded) <= length {
			t.Fatalf("pkcs7Pad(%d bytes) length %d, want more than input (padding must always be added)", length, len(padded))
		}
		got, err := pkcs7Unpad(padded, 16)
		if err != nil {
			t.Fatalf("pkcs7Unpad(%d bytes): %v", length, err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("pkcs7Unpad round trip(%d bytes) = %x, want %x", length, got, data)
		}
	}
}

func TestPKCS7UnpadRejectsInvalidPadding(t *testing.T) {
	cases := map[string][]byte{
		"zero pad length":          append(bytes.Repeat([]byte{0x01}, 15), 0x00),
		"pad length exceeds block": append(bytes.Repeat([]byte{0x01}, 15), 0x11),
		"inconsistent pad bytes":   append(bytes.Repeat([]byte{0x01}, 13), 0x03, 0x03, 0x02),
		"empty input":              {},
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := pkcs7Unpad(data, 16); err == nil {
				t.Fatalf("pkcs7Unpad(%s) = nil error, want error", name)
			}
		})
	}
}

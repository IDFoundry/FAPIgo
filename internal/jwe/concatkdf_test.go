package jwe

import (
	"bytes"
	"testing"
)

func TestConcatKDFDeterministic(t *testing.T) {
	z := []byte("shared-secret-material")
	info := otherInfo("ECDH-ES+A256KW", nil, nil, 256)
	a := concatKDF(z, 256, info)
	b := concatKDF(z, 256, info)
	if !bytes.Equal(a, b) {
		t.Fatalf("concatKDF is not deterministic: %x != %x", a, b)
	}
}

func TestConcatKDFOutputLength(t *testing.T) {
	z := []byte("shared-secret-material")
	for _, bits := range []int{128, 192, 256, 384, 512} {
		out := concatKDF(z, bits, otherInfo("A256GCM", nil, nil, bits))
		if len(out) != bits/8 {
			t.Fatalf("concatKDF(bits=%d) len = %d, want %d", bits, len(out), bits/8)
		}
	}
}

// 384 and 512 bits require 2 and 2 SHA-256 (32-byte) hash iterations
// respectively (ceil(48/32)=2, ceil(64/32)=2) — this exercises the
// multi-repetition path, not just the single-hash-block common case.
func TestConcatKDFMultipleRepetitions(t *testing.T) {
	z := []byte("shared-secret-material")
	info := otherInfo("A256GCM", nil, nil, 512)
	out := concatKDF(z, 512, info)
	if len(out) != 64 {
		t.Fatalf("len(out) = %d, want 64", len(out))
	}
	// The first 32 bytes must equal a single-repetition derivation of
	// the same length prefix (counter=1 is independent of how many
	// total repetitions are needed).
	first32 := concatKDF(z, 256, info)
	if !bytes.Equal(out[:32], first32) {
		t.Fatalf("first repetition mismatch: %x != %x", out[:32], first32)
	}
}

// Every input concatKDF/otherInfo take part in binding the derived key
// to this specific agreement — changing any one of them must change the
// output, or the KDF would be leaking key material across contexts that
// should be cryptographically distinct.
func TestConcatKDFSensitiveToEveryInput(t *testing.T) {
	baseline := concatKDF([]byte("z"), 256, otherInfo("ECDH-ES+A256KW", []byte("apu"), []byte("apv"), 256))

	cases := map[string][]byte{
		"different z":           concatKDF([]byte("different-z"), 256, otherInfo("ECDH-ES+A256KW", []byte("apu"), []byte("apv"), 256)),
		"different algorithmID": concatKDF([]byte("z"), 256, otherInfo("A256GCM", []byte("apu"), []byte("apv"), 256)),
		"different apu":         concatKDF([]byte("z"), 256, otherInfo("ECDH-ES+A256KW", []byte("different-apu"), []byte("apv"), 256)),
		"different apv":         concatKDF([]byte("z"), 256, otherInfo("ECDH-ES+A256KW", []byte("apu"), []byte("different-apv"), 256)),
		"different keyDataLen":  concatKDF([]byte("z"), 128, otherInfo("ECDH-ES+A256KW", []byte("apu"), []byte("apv"), 128)),
	}
	for name, got := range cases {
		if bytes.Equal(got, baseline[:len(got)]) {
			t.Errorf("%s: output unchanged from baseline, want it to differ", name)
		}
	}
}

func TestOtherInfoLengthPrefixing(t *testing.T) {
	// AlgorithmID "AB" (2 bytes), apu "C" (1 byte), apv nil (0 bytes),
	// keyDataLenBits 256 — hand-verify the exact byte layout against
	// RFC 7518 §4.6.2's Datalen || Data construction for each field.
	got := otherInfo("AB", []byte("C"), nil, 256)
	want := []byte{
		0, 0, 0, 2, 'A', 'B', // AlgorithmID: length 2, "AB"
		0, 0, 0, 1, 'C', // PartyUInfo: length 1, "C"
		0, 0, 0, 0, // PartyVInfo: length 0, empty
		0, 0, 1, 0, // SuppPubInfo: 256 as a 32-bit big-endian integer
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("otherInfo(...) = %x, want %x", got, want)
	}
}

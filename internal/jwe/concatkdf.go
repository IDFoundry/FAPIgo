package jwe

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
)

// concatKDF derives keyDataLenBits bits from the shared secret z using
// SHA-256, per the Concatenation Key Derivation Function (NIST SP
// 800-56A §5.8.1, as profiled for JOSE by RFC 7518 Appendix B). otherInfo
// is the caller-assembled OtherInfo octet string (see otherInfo below).
//
// This exists because ECDH-ES-based key management (RFC 7518 §4.6) has
// no other way to turn a raw ECDH shared secret into a key: unlike
// RSA-OAEP, where crypto/rsa does the entire key-management step, Go's
// standard library has no Concat KDF implementation.
func concatKDF(z []byte, keyDataLenBits int, otherInfo []byte) []byte {
	const hashLen = sha256.Size
	keyDataLenBytes := keyDataLenBits / 8
	reps := (keyDataLenBytes + hashLen - 1) / hashLen

	out := make([]byte, 0, reps*hashLen)
	var counter [4]byte
	for i := 1; i <= reps; i++ {
		binary.BigEndian.PutUint32(counter[:], uint32(i))
		h := sha256.New()
		h.Write(counter[:])
		h.Write(z)
		h.Write(otherInfo)
		out = h.Sum(out)
	}
	return out[:keyDataLenBytes]
}

// otherInfo assembles the OtherInfo octet string RFC 7518 Appendix B
// defines for ECDH-ES key derivation: AlgorithmID || PartyUInfo ||
// PartyVInfo || SuppPubInfo. algorithmID is the ASCII "alg" (for a key-
// wrapping algorithm like ECDH-ES+A256KW) or "enc" (for direct
// agreement) value being derived for. apu/apv are the "apu"/"apv" header
// values if present, or nil for either (an absent value contributes an
// empty octet string, not an error — RFC 7518 §4.6.1.1). keyDataLenBits
// is the length, in bits, of the key material being derived — the same
// value passed to concatKDF.
func otherInfo(algorithmID string, apu, apv []byte, keyDataLenBits int) ([]byte, error) {
	if keyDataLenBits < 0 || keyDataLenBits > math.MaxUint32 {
		return nil, fmt.Errorf("jwe: key data length %d bits out of range", keyDataLenBits)
	}
	algID, err := lengthPrefixed([]byte(algorithmID))
	if err != nil {
		return nil, err
	}
	u, err := lengthPrefixed(apu)
	if err != nil {
		return nil, err
	}
	v, err := lengthPrefixed(apv)
	if err != nil {
		return nil, err
	}
	out := append(algID, u...)
	out = append(out, v...)
	var suppPubInfo [4]byte
	binary.BigEndian.PutUint32(suppPubInfo[:], uint32(keyDataLenBits))
	out = append(out, suppPubInfo[:]...)
	// SuppPrivInfo is optional and RFC 7518's own OtherInfo construction
	// never sets it — omitted entirely, not even as a zero-length field.
	return out, nil
}

// lengthPrefixed returns b prefixed with its own length as a 32-bit
// big-endian integer, the "Datalen || Data" encoding RFC 7518 §4.6.2
// uses for each OtherInfo component. b is always a short, fixed program
// value in this package (an algorithm identifier or an apu/apv header
// value this package itself never sets), never attacker-controlled
// length, but the bound is checked explicitly rather than assumed.
func lengthPrefixed(b []byte) ([]byte, error) {
	n := len(b)
	if n < 0 || n > math.MaxUint32 {
		return nil, fmt.Errorf("jwe: value of length %d exceeds maximum encodable length", n)
	}
	out := make([]byte, 4+n)
	binary.BigEndian.PutUint32(out, uint32(n))
	copy(out[4:], b)
	return out, nil
}

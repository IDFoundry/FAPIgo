package jwe

import (
	"crypto/aes"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
)

// aesKeyWrapIV is the default initial value RFC 3394 §2.2.3.1 fixes for
// AES Key Wrap: the 64-bit constant 0xA6A6A6A6A6A6A6A6.
var aesKeyWrapIV = [8]byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

// aesKeyWrap wraps plaintext (which must be a multiple of 8 bytes, at
// least 16) under kek using AES Key Wrap (RFC 3394), returning
// ciphertext 8 bytes longer than plaintext. This exists because JOSE's
// ECDH-ES+A256KW key management (RFC 7518 §4.7) wraps the CEK this way,
// and Go's standard library has no AES Key Wrap implementation — only
// the underlying AES block cipher this function builds on
// (crypto/aes.NewCipher).
func aesKeyWrap(kek, plaintext []byte) ([]byte, error) {
	if len(plaintext) < 16 || len(plaintext)%8 != 0 {
		return nil, fmt.Errorf("jwe: key wrap plaintext must be a multiple of 8 bytes, at least 16, got %d", len(plaintext))
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("jwe: key wrap: %w", err)
	}

	n := len(plaintext) / 8
	r := make([][8]byte, n)
	for i := range r {
		copy(r[i][:], plaintext[i*8:(i+1)*8])
	}

	a := aesKeyWrapIV
	var buf [16]byte
	for j := 0; j <= 5; j++ {
		for i := 1; i <= n; i++ {
			copy(buf[:8], a[:])
			copy(buf[8:], r[i-1][:])
			block.Encrypt(buf[:], buf[:])

			var t [8]byte
			binary.BigEndian.PutUint64(t[:], uint64(n*j+i))
			for k := range a {
				a[k] = buf[k] ^ t[k]
			}
			copy(r[i-1][:], buf[8:])
		}
	}

	out := make([]byte, 8+len(plaintext))
	copy(out[:8], a[:])
	for i, block := range r {
		copy(out[8+i*8:], block[:])
	}
	return out, nil
}

// aesKeyUnwrap reverses aesKeyWrap, returning an error (never a
// plaintext) if the integrity check RFC 3394 §2.2.2 requires — the
// recovered A value matching the fixed IV — fails. ciphertext must be at
// least 24 bytes and a multiple of 8.
func aesKeyUnwrap(kek, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 24 || len(ciphertext)%8 != 0 {
		return nil, fmt.Errorf("jwe: key unwrap ciphertext must be a multiple of 8 bytes, at least 24, got %d", len(ciphertext))
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("jwe: key unwrap: %w", err)
	}

	n := len(ciphertext)/8 - 1
	var a [8]byte
	copy(a[:], ciphertext[:8])
	r := make([][8]byte, n)
	for i := range r {
		copy(r[i][:], ciphertext[8+i*8:8+(i+1)*8])
	}

	var buf [16]byte
	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			var t [8]byte
			binary.BigEndian.PutUint64(t[:], uint64(n*j+i))
			var axort [8]byte
			for k := range a {
				axort[k] = a[k] ^ t[k]
			}
			copy(buf[:8], axort[:])
			copy(buf[8:], r[i-1][:])
			block.Decrypt(buf[:], buf[:])

			copy(a[:], buf[:8])
			copy(r[i-1][:], buf[8:])
		}
	}

	if subtle.ConstantTimeCompare(a[:], aesKeyWrapIV[:]) != 1 {
		return nil, fmt.Errorf("jwe: key unwrap integrity check failed")
	}

	out := make([]byte, n*8)
	for i, block := range r {
		copy(out[i*8:], block[:])
	}
	return out, nil
}

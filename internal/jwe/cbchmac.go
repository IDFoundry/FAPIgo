package jwe

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"math"
)

// sealCBCHMAC encrypts plaintext under cek and iv with
// AES_256_CBC_HMAC_SHA_512 (RFC 7518 §5.2.2.1/§5.2.5): cek is split
// into MAC_KEY (its initial 32 octets) and ENC_KEY (its final 32
// octets), plaintext is PKCS#7-padded and CBC-encrypted under iv with
// ENC_KEY, and the returned tag is the leftmost 32 octets of
// HMAC-SHA-512 computed over aad || iv || ciphertext || AL, where AL is
// aad's bit length as a big-endian uint64 — this is encrypt-then-MAC,
// unlike A256GCM's single AEAD call.
func sealCBCHMAC(cek, iv, plaintext, aad []byte) (ciphertext, tag []byte, err error) {
	if len(cek) != cekSizeA256CBCHS512 {
		return nil, nil, fmt.Errorf("jwe: a256cbc-hs512: cek must be %d bytes, got %d", cekSizeA256CBCHS512, len(cek))
	}
	macKey, encKey := cek[:32], cek[32:]

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, nil, fmt.Errorf("jwe: a256cbc-hs512: %w", err)
	}
	if len(iv) != block.BlockSize() {
		return nil, nil, fmt.Errorf("jwe: a256cbc-hs512: iv must be %d bytes, got %d", block.BlockSize(), len(iv))
	}

	padded, err := pkcs7Pad(plaintext, block.BlockSize())
	if err != nil {
		return nil, nil, err
	}
	ciphertext = make([]byte, len(padded))
	// RFC 7518 §5.2.2.1 defines AES_CBC_HMAC_SHA2 directly in terms of
	// plain CBC for confidentiality plus a separate HMAC for integrity
	// (encrypt-then-MAC) — this is not bare CBC standing in as the
	// entire construction's authentication, the way a naive CBC-only
	// scheme would be. cbcHMACTag below is that separate MAC; there is
	// no "secure mode" substitute that would still implement this
	// standard's own composition.
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded) // NOSONAR: go:S5542 — CBC + separate HMAC is what RFC 7518 §5.2.2.1 requires, see comment above

	return ciphertext, cbcHMACTag(macKey, aad, iv, ciphertext), nil
}

// openCBCHMAC reverses sealCBCHMAC, verifying tag before ever touching
// ciphertext's contents. That ordering — authenticate, then decrypt —
// is load-bearing, not stylistic: CBC with PKCS#7 padding is the
// textbook padding-oracle construction (Vaudenay), and the only reason
// it's safe here is that an attacker can never get this package to run
// CBC-decrypt/depad on ciphertext it doesn't already know is
// authentic. Reordering this to decrypt-then-verify would reopen
// exactly that oracle.
func openCBCHMAC(cek, iv, ciphertext, tag, aad []byte) ([]byte, error) {
	if len(cek) != cekSizeA256CBCHS512 {
		return nil, fmt.Errorf("jwe: a256cbc-hs512: cek must be %d bytes, got %d", cekSizeA256CBCHS512, len(cek))
	}
	macKey, encKey := cek[:32], cek[32:]

	if !hmac.Equal(cbcHMACTag(macKey, aad, iv, ciphertext), tag) {
		return nil, fmt.Errorf("%w: tag mismatch", ErrDecryptionFailed)
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("jwe: a256cbc-hs512: %w", err)
	}
	if len(iv) != block.BlockSize() {
		return nil, fmt.Errorf("%w: invalid iv size", ErrDecryptionFailed)
	}
	if len(ciphertext) == 0 || len(ciphertext)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("%w: invalid ciphertext length", ErrDecryptionFailed)
	}

	padded := make([]byte, len(ciphertext))
	// See the matching comment in sealCBCHMAC: this CBC decrypt only
	// ever runs after the HMAC tag above has already been verified, so
	// it's the same encrypt-then-MAC construction in reverse, not bare
	// CBC providing authentication on its own.
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(padded, ciphertext) // NOSONAR: go:S5542 — CBC + separate HMAC is what RFC 7518 §5.2.2.1 requires, see sealCBCHMAC's comment

	plaintext, err := pkcs7Unpad(padded, block.BlockSize())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}
	return plaintext, nil
}

// cbcHMACTag computes the RFC 7518 §5.2.2.1 authentication tag: the
// leftmost cbcHMACTagSize octets of HMAC-SHA-512(macKey, aad || iv ||
// ciphertext || AL), where AL is aad's bit length as a big-endian
// uint64 ("the octet string AL is equal to the number of bits in the
// Additional Authenticated Data A expressed as a 64-bit unsigned
// big-endian integer").
func cbcHMACTag(macKey, aad, iv, ciphertext []byte) []byte {
	var al [8]byte
	binary.BigEndian.PutUint64(al[:], uint64(len(aad))*8)

	mac := hmac.New(sha512.New, macKey)
	mac.Write(aad)
	mac.Write(iv)
	mac.Write(ciphertext)
	mac.Write(al[:])
	return mac.Sum(nil)[:cbcHMACTagSize]
}

// pkcs7Pad pads data to a multiple of blockSize per PKCS #7 (RFC 7518
// §5.2.2.1's "CBC encrypted using PKCS #7 padding"): every byte of
// padding carries the pad length, and at least one full block of
// padding is always added, even when len(data) is already a multiple
// of blockSize.
func pkcs7Pad(data []byte, blockSize int) ([]byte, error) {
	padLen := blockSize - len(data)%blockSize
	// blockSize is always AES's 16-byte block size in this package's
	// only caller, so padLen is always in [1, 16] — this bound only
	// exists so gosec's G115 narrowing check can see padLen is safe to
	// convert to a byte below, the same reason lengthPrefixed
	// (concatkdf.go) checks its own length before narrowing it.
	if padLen <= 0 || padLen > math.MaxUint8 {
		return nil, fmt.Errorf("jwe: invalid pkcs7 pad length %d", padLen)
	}
	padded := make([]byte, len(data)+padLen)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}
	return padded, nil
}

// pkcs7Unpad reverses pkcs7Pad. Only ever called after openCBCHMAC has
// already verified the HMAC tag over this exact ciphertext, so unlike
// a general-purpose PKCS#7 unpad, there is no attacker-observable
// padding-oracle surface here: an attacker who could get this far
// already had to produce a validly-tagged ciphertext.
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	n := len(data)
	if n == 0 || n%blockSize != 0 {
		return nil, fmt.Errorf("jwe: a256cbc-hs512: padded length is not a multiple of the block size")
	}
	padLen := int(data[n-1])
	if padLen == 0 || padLen > blockSize || padLen > n {
		return nil, fmt.Errorf("jwe: a256cbc-hs512: invalid padding length")
	}
	for _, b := range data[n-padLen:] {
		if int(b) != padLen {
			return nil, fmt.Errorf("jwe: a256cbc-hs512: invalid padding")
		}
	}
	return data[:n-padLen], nil
}

package jwe

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	fapi "github.com/idfoundry/fapigo"
)

// cekSize is the content-encryption key size in bytes for A256GCM — the
// only ContentEncryptionAlgorithm this package supports.
const cekSize = 32

// gcmNonceSize is the IV size RFC 7518 §5.3 requires for the AES-GCM
// content-encryption family: 96 bits.
const gcmNonceSize = 12

// minRSAModulusBits is the minimum RSA key size RSAOAEP256 accepts,
// matching internal/jose's own floor for PS256 — a caller-supplied RSA
// key this small enough to factor would let an attacker recover the
// wrapped CEK and defeat the encryption entirely.
const minRSAModulusBits = 2048

// EncryptRequest describes one JWE to produce.
type EncryptRequest struct {
	// Algorithm selects the key-management algorithm (the "alg" header)
	// and, with it, which concrete type RecipientKey must be:
	// *rsa.PublicKey for RSAOAEP256, *ecdh.PublicKey for ECDHESA256KW.
	Algorithm fapi.KeyManagementAlgorithm

	// Encryption selects the content-encryption algorithm (the "enc"
	// header). Currently always A256GCM — the field exists so a future
	// second value doesn't change this function's signature.
	Encryption fapi.ContentEncryptionAlgorithm

	RecipientKey any

	// KeyID, if non-empty, is embedded as the header's "kid" — which of
	// the recipient's possibly several encryption keys this was
	// encrypted to.
	KeyID string

	// ContentType, if non-empty, is embedded as the header's "cty" —
	// e.g. "JWT" for a nested JWT (OIDC Core §10.2). This package
	// attaches no meaning to it itself.
	ContentType string

	// Random is the source of randomness for the CEK, the IV, and (for
	// ECDHESA256KW) the ephemeral key pair. crypto/rand.Reader if nil.
	Random io.Reader

	Plaintext []byte
}

// Encrypt produces a JWE in compact serialization for req.
func Encrypt(req EncryptRequest) (string, error) {
	if !req.Algorithm.IsValid() {
		return "", fmt.Errorf("jwe: invalid key management algorithm %v", req.Algorithm)
	}
	if req.Encryption != fapi.A256GCM {
		return "", fmt.Errorf("jwe: invalid content encryption algorithm %v", req.Encryption)
	}
	random := req.Random
	if random == nil {
		random = rand.Reader
	}

	cek := make([]byte, cekSize)
	if _, err := io.ReadFull(random, cek); err != nil {
		return "", fmt.Errorf("jwe: generate cek: %w", err)
	}

	encryptedKey, epk, err := wrapCEK(req.Algorithm, req.RecipientKey, cek, random)
	if err != nil {
		return "", err
	}

	headerJSON, err := marshalHeader(Header{
		Algorithm: req.Algorithm, Encryption: req.Encryption,
		ContentType: req.ContentType, KeyID: req.KeyID, EphemeralPublicKey: epk,
	})
	if err != nil {
		return "", fmt.Errorf("jwe: marshal header: %w", err)
	}
	protected := base64.RawURLEncoding.EncodeToString(headerJSON)

	iv := make([]byte, gcmNonceSize)
	if _, err := io.ReadFull(random, iv); err != nil {
		return "", fmt.Errorf("jwe: generate iv: %w", err)
	}
	ciphertext, tag, err := seal(cek, iv, req.Plaintext, []byte(protected))
	if err != nil {
		return "", err
	}

	return strings.Join([]string{
		protected,
		base64.RawURLEncoding.EncodeToString(encryptedKey),
		base64.RawURLEncoding.EncodeToString(iv),
		base64.RawURLEncoding.EncodeToString(ciphertext),
		base64.RawURLEncoding.EncodeToString(tag),
	}, "."), nil
}

// wrapCEK delivers cek to recipientKey under alg, returning the
// encrypted_key compact-serialization component and — for an
// ECDH-ES-family algorithm — the ephemeral public key to embed as the
// header's "epk" (nil for RSAOAEP256).
func wrapCEK(alg fapi.KeyManagementAlgorithm, recipientKey any, cek []byte, random io.Reader) ([]byte, *ecdh.PublicKey, error) {
	switch alg {
	case fapi.RSAOAEP256:
		pub, ok := recipientKey.(*rsa.PublicKey)
		if !ok {
			return nil, nil, fmt.Errorf("jwe: RSAOAEP256 requires an *rsa.PublicKey, got %T", recipientKey)
		}
		if pub.N == nil || pub.N.BitLen() < minRSAModulusBits {
			return nil, nil, fmt.Errorf("jwe: RSAOAEP256 requires an RSA key of at least %d bits", minRSAModulusBits)
		}
		encryptedKey, err := rsa.EncryptOAEP(sha256.New(), random, pub, cek, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("jwe: rsa-oaep-256 wrap: %w", err)
		}
		return encryptedKey, nil, nil

	case fapi.ECDHESA256KW:
		pub, ok := recipientKey.(*ecdh.PublicKey)
		if !ok || pub.Curve() != ecdh.P256() {
			return nil, nil, fmt.Errorf("jwe: ECDHESA256KW requires a P-256 *ecdh.PublicKey, got %T", recipientKey)
		}
		ephemeral, err := ecdh.P256().GenerateKey(random)
		if err != nil {
			return nil, nil, fmt.Errorf("jwe: generate ephemeral key: %w", err)
		}
		z, err := ephemeral.ECDH(pub)
		if err != nil {
			return nil, nil, fmt.Errorf("jwe: ecdh: %w", err)
		}
		const kekSizeBits = 256 // AES-256 Key Wrap's own key size
		info, err := otherInfo(alg.String(), nil, nil, kekSizeBits)
		if err != nil {
			return nil, nil, fmt.Errorf("jwe: %w", err)
		}
		kek := concatKDF(z, kekSizeBits, info)
		encryptedKey, err := aesKeyWrap(kek, cek)
		if err != nil {
			return nil, nil, fmt.Errorf("jwe: ecdh-es+a256kw wrap: %w", err)
		}
		return encryptedKey, ephemeral.PublicKey(), nil

	default:
		return nil, nil, fmt.Errorf("jwe: unsupported key management algorithm %v", alg)
	}
}

// seal encrypts plaintext under cek with A256GCM, returning ciphertext
// and its authentication tag as separate values — RFC 7516's compact
// serialization carries them in separate components, unlike Go's
// cipher.AEAD.Seal, which appends the tag to the ciphertext it returns.
func seal(cek, iv, plaintext, aad []byte) (ciphertext, tag []byte, err error) {
	gcm, err := newGCM(cek)
	if err != nil {
		return nil, nil, err
	}
	sealed := gcm.Seal(nil, iv, plaintext, aad)
	return sealed[:len(sealed)-gcm.Overhead()], sealed[len(sealed)-gcm.Overhead():], nil
}

func newGCM(cek []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, fmt.Errorf("jwe: a256gcm: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("jwe: a256gcm: %w", err)
	}
	return gcm, nil
}

// DecryptRequest describes one JWE to open. Algorithm and Encryption are
// what the caller requires — never derived from the token's own header
// — so a header claiming a different algorithm than expected is
// rejected outright, the same policy internal/jose applies to a JWS
// "alg" header.
type DecryptRequest struct {
	Algorithm  fapi.KeyManagementAlgorithm
	Encryption fapi.ContentEncryptionAlgorithm

	// RecipientKey must be *rsa.PrivateKey for RSAOAEP256 or
	// *ecdh.PrivateKey for ECDHESA256KW.
	RecipientKey any

	Compact string
}

// DecryptResult is a successfully decrypted and authenticated JWE.
type DecryptResult struct {
	Plaintext []byte
	Header    Header
}

// Decrypt opens req.Compact, returning an error if it is malformed, its
// header doesn't match what the caller required, or authentication
// fails for any reason (wrong key, tampered ciphertext or tag, or a
// failed ECDH-ES+A256KW key-unwrap integrity check).
func Decrypt(req DecryptRequest) (DecryptResult, error) {
	if !req.Algorithm.IsValid() {
		return DecryptResult{}, fmt.Errorf("jwe: invalid key management algorithm %v", req.Algorithm)
	}
	if req.Encryption != fapi.A256GCM {
		return DecryptResult{}, fmt.Errorf("jwe: invalid content encryption algorithm %v", req.Encryption)
	}

	parts := strings.Split(req.Compact, ".")
	if len(parts) != 5 {
		return DecryptResult{}, fmt.Errorf("%w: expected 5 segments, got %d", ErrMalformed, len(parts))
	}
	// Every segment except the ciphertext must be non-empty: the header,
	// encrypted key, IV and tag are always present for both algorithms
	// this package supports. The ciphertext, though, is legitimately
	// empty when the plaintext itself was empty (RFC 7516 §5.1: AES-GCM
	// produces zero ciphertext bytes for zero plaintext bytes — only the
	// tag is non-empty).
	for i, p := range parts {
		if i == 3 {
			continue
		}
		if p == "" {
			return DecryptResult{}, fmt.Errorf("%w: empty segment", ErrMalformed)
		}
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return DecryptResult{}, fmt.Errorf("%w: header: %v", ErrMalformed, err)
	}
	header, err := parseHeader(headerJSON)
	if err != nil {
		return DecryptResult{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if header.Algorithm != req.Algorithm || header.Encryption != req.Encryption {
		return DecryptResult{}, ErrAlgorithmMismatch
	}

	encryptedKey, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return DecryptResult{}, fmt.Errorf("%w: encrypted key: %v", ErrMalformed, err)
	}
	iv, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return DecryptResult{}, fmt.Errorf("%w: iv: %v", ErrMalformed, err)
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return DecryptResult{}, fmt.Errorf("%w: ciphertext: %v", ErrMalformed, err)
	}
	tag, err := base64.RawURLEncoding.DecodeString(parts[4])
	if err != nil {
		return DecryptResult{}, fmt.Errorf("%w: tag: %v", ErrMalformed, err)
	}

	cek, err := unwrapCEK(req.Algorithm, req.RecipientKey, encryptedKey, header.EphemeralPublicKey)
	if err != nil {
		return DecryptResult{}, err
	}

	plaintext, err := open(cek, iv, ciphertext, tag, []byte(parts[0]))
	if err != nil {
		return DecryptResult{}, err
	}
	return DecryptResult{Plaintext: plaintext, Header: header}, nil
}

func unwrapCEK(alg fapi.KeyManagementAlgorithm, recipientKey any, encryptedKey []byte, epk *ecdh.PublicKey) ([]byte, error) {
	switch alg {
	case fapi.RSAOAEP256:
		priv, ok := recipientKey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("jwe: RSAOAEP256 requires an *rsa.PrivateKey, got %T", recipientKey)
		}
		if priv.N == nil || priv.N.BitLen() < minRSAModulusBits {
			return nil, fmt.Errorf("jwe: RSAOAEP256 requires an RSA key of at least %d bits", minRSAModulusBits)
		}
		cek, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, encryptedKey, nil)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
		}
		return cek, nil

	case fapi.ECDHESA256KW:
		priv, ok := recipientKey.(*ecdh.PrivateKey)
		if !ok || priv.Curve() != ecdh.P256() {
			return nil, fmt.Errorf("jwe: ECDHESA256KW requires a P-256 *ecdh.PrivateKey, got %T", recipientKey)
		}
		if epk == nil {
			return nil, fmt.Errorf("%w: missing epk", ErrMalformed)
		}
		z, err := priv.ECDH(epk)
		if err != nil {
			return nil, fmt.Errorf("%w: ecdh: %v", ErrDecryptionFailed, err)
		}
		const kekSizeBits = 256
		info, err := otherInfo(alg.String(), nil, nil, kekSizeBits)
		if err != nil {
			return nil, fmt.Errorf("jwe: %w", err)
		}
		kek := concatKDF(z, kekSizeBits, info)
		cek, err := aesKeyUnwrap(kek, encryptedKey)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
		}
		return cek, nil

	default:
		return nil, fmt.Errorf("jwe: unsupported key management algorithm %v", alg)
	}
}

func open(cek, iv, ciphertext, tag, aad []byte) ([]byte, error) {
	gcm, err := newGCM(cek)
	if err != nil {
		return nil, err
	}
	sealed := make([]byte, 0, len(ciphertext)+len(tag))
	sealed = append(sealed, ciphertext...)
	sealed = append(sealed, tag...)
	plaintext, err := gcm.Open(nil, iv, sealed, aad)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}
	return plaintext, nil
}

package jwe

import (
	"context"
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

// cekSizeA256GCM is the content-encryption key size in bytes for
// A256GCM.
const cekSizeA256GCM = 32

// cekSizeA256CBCHS512 is the content-encryption key size in bytes for
// A256CBC-HS512 (RFC 7518 §5.2.5): a 64-octet K, split into a 32-octet
// MAC_KEY (the initial half) and a 32-octet ENC_KEY (the final half) —
// see §5.2.2.1's "MAC_KEY consists of the initial MAC_KEY_LEN octets of
// K...ENC_KEY consists of the final ENC_KEY_LEN octets of K".
const cekSizeA256CBCHS512 = 64

// gcmNonceSize is the IV size RFC 7518 §5.3 requires for the AES-GCM
// content-encryption family: 96 bits.
const gcmNonceSize = 12

// cbcIVSize is the IV size RFC 7518 §5.2.2.1 requires for the
// CBC-HMAC content-encryption family: 128 bits.
const cbcIVSize = 16

// cbcHMACTagSize is T_LEN for AES_256_CBC_HMAC_SHA_512 (RFC 7518
// §5.2.5): the authentication tag is the leftmost 32 octets (256 bits)
// of the full HMAC-SHA-512 output, not the full 64-octet output.
const cbcHMACTagSize = 32

// cekSizeFor returns the content-encryption key size in bytes for enc.
// Only called after enc.IsValid() — the default case can't be reached
// in practice, but is kept for the same defensive-symmetry reason
// wrapCEK/UnwrapCEK keep their own "unsupported algorithm" default arm
// despite an earlier IsValid() check.
func cekSizeFor(enc fapi.ContentEncryptionAlgorithm) (int, error) {
	switch enc {
	case fapi.A256GCM:
		return cekSizeA256GCM, nil
	case fapi.A256CBCHS512:
		return cekSizeA256CBCHS512, nil
	default:
		return 0, fmt.Errorf("jwe: unsupported content encryption algorithm %v", enc)
	}
}

// ivSizeFor returns the IV size in bytes for enc.
func ivSizeFor(enc fapi.ContentEncryptionAlgorithm) (int, error) {
	switch enc {
	case fapi.A256GCM:
		return gcmNonceSize, nil
	case fapi.A256CBCHS512:
		return cbcIVSize, nil
	default:
		return 0, fmt.Errorf("jwe: unsupported content encryption algorithm %v", enc)
	}
}

// sealContent encrypts plaintext under cek and iv with enc, returning
// ciphertext and its authentication tag as separate values.
func sealContent(enc fapi.ContentEncryptionAlgorithm, cek, iv, plaintext, aad []byte) (ciphertext, tag []byte, err error) {
	switch enc {
	case fapi.A256GCM:
		return seal(cek, iv, plaintext, aad)
	case fapi.A256CBCHS512:
		return sealCBCHMAC(cek, iv, plaintext, aad)
	default:
		return nil, nil, fmt.Errorf("jwe: unsupported content encryption algorithm %v", enc)
	}
}

// openContent decrypts and authenticates ciphertext/tag under cek and
// iv with enc.
func openContent(enc fapi.ContentEncryptionAlgorithm, cek, iv, ciphertext, tag, aad []byte) ([]byte, error) {
	switch enc {
	case fapi.A256GCM:
		return open(cek, iv, ciphertext, tag, aad)
	case fapi.A256CBCHS512:
		return openCBCHMAC(cek, iv, ciphertext, tag, aad)
	default:
		return nil, fmt.Errorf("jwe: unsupported content encryption algorithm %v", enc)
	}
}

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
	// header): A256GCM or A256CBC-HS512.
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
	cekLen, err := cekSizeFor(req.Encryption)
	if err != nil {
		return "", err
	}
	random := req.Random
	if random == nil {
		random = rand.Reader
	}

	cek := make([]byte, cekLen)
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

	ivLen, err := ivSizeFor(req.Encryption)
	if err != nil {
		return "", err
	}
	iv := make([]byte, ivLen)
	if _, err := io.ReadFull(random, iv); err != nil {
		return "", fmt.Errorf("jwe: generate iv: %w", err)
	}
	ciphertext, tag, err := sealContent(req.Encryption, cek, iv, req.Plaintext, []byte(protected))
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

	// RecipientKey is either a concrete private key this package unwraps
	// with directly (*rsa.PrivateKey for RSAOAEP256, *ecdh.PrivateKey for
	// ECDHESA256KW), or a value implementing Unwrapper — for a caller
	// that never holds the raw private key itself (e.g. an HSM- or
	// remote-signing-service-backed key manager), and so cannot hand one
	// to this package at all.
	RecipientKey any

	Compact string
}

// Unwrapper delivers the content-encryption key for one JWE without
// this package (or its caller) ever holding the recipient's private
// key — the decryption-side equivalent of how this module's signing
// path never hands a crypto.Signer or raw private key across a
// KeyManager boundary. ctx is threaded through unchanged, so an
// implementation backed by a remote call can honor cancellation the
// same way keys.KeyManager.Sign does.
type Unwrapper interface {
	UnwrapCEK(ctx context.Context, alg fapi.KeyManagementAlgorithm, encryptedKey []byte, ephemeralPublicKey *ecdh.PublicKey) ([]byte, error)
}

// DecryptResult is a successfully decrypted and authenticated JWE.
type DecryptResult struct {
	Plaintext []byte
	Header    Header
}

// Decrypt opens req.Compact, returning an error if it is malformed, its
// header doesn't match what the caller required, or authentication
// fails for any reason (wrong key, tampered ciphertext or tag, or a
// failed ECDH-ES+A256KW key-unwrap integrity check). ctx is only used
// when req.RecipientKey is an Unwrapper.
func Decrypt(ctx context.Context, req DecryptRequest) (DecryptResult, error) {
	if !req.Algorithm.IsValid() {
		return DecryptResult{}, fmt.Errorf("jwe: invalid key management algorithm %v", req.Algorithm)
	}
	if !req.Encryption.IsValid() {
		return DecryptResult{}, fmt.Errorf("jwe: invalid content encryption algorithm %v", req.Encryption)
	}

	parts := strings.Split(req.Compact, ".")
	if len(parts) != 5 {
		return DecryptResult{}, fmt.Errorf("%w: expected 5 segments, got %d", ErrMalformed, len(parts))
	}
	// Every segment except the ciphertext must be non-empty: the header,
	// encrypted key, IV and tag are always present for every algorithm
	// this package supports. The ciphertext, though, is legitimately
	// empty for A256GCM when the plaintext itself was empty (RFC 7516
	// §5.1: AES-GCM produces zero ciphertext bytes for zero plaintext
	// bytes — only the tag is non-empty); the header isn't parsed yet
	// at this point, so this check can't be conditioned on which
	// algorithm is in play. A256CBC-HS512's ciphertext is never
	// actually empty (PKCS#7 padding always emits at least one block),
	// but that's enforced by openCBCHMAC itself, not here.
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

	var cek []byte
	if unwrapper, ok := req.RecipientKey.(Unwrapper); ok {
		cek, err = unwrapper.UnwrapCEK(ctx, req.Algorithm, encryptedKey, header.EphemeralPublicKey)
		if err != nil {
			return DecryptResult{}, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
		}
	} else {
		cek, err = UnwrapCEK(req.Algorithm, req.RecipientKey, encryptedKey, header.EphemeralPublicKey)
		if err != nil {
			return DecryptResult{}, err
		}
	}

	plaintext, err := openContent(req.Encryption, cek, iv, ciphertext, tag, []byte(parts[0]))
	if err != nil {
		return DecryptResult{}, err
	}
	return DecryptResult{Plaintext: plaintext, Header: header}, nil
}

// UnwrapCEK recovers the content-encryption key encryptedKey carries,
// using recipientKey directly (*rsa.PrivateKey for RSAOAEP256,
// *ecdh.PrivateKey for ECDHESA256KW — epk is required for the latter,
// ignored for the former). Exported so a KeyManager-backed Unwrapper
// implementation that does hold a concrete private key in memory (e.g.
// keys/ephemeral, for tests) can reuse this package's own
// already-verified ECDH-ES+A256KW unwrap logic rather than
// reimplementing the Concat KDF and AES Key Wrap itself.
func UnwrapCEK(alg fapi.KeyManagementAlgorithm, recipientKey any, encryptedKey []byte, epk *ecdh.PublicKey) ([]byte, error) {
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
		return UnwrapCEKFromSharedSecret(alg, z, encryptedKey)

	default:
		return nil, fmt.Errorf("jwe: unsupported key management algorithm %v", alg)
	}
}

// UnwrapCEKFromSharedSecret recovers the content-encryption key
// encryptedKey carries given z, an ECDH shared secret already agreed
// with the epk embedded in the JWE header — the Concat-KDF (RFC 7518
// Appendix B) and RFC-3394 AES-Unwrap steps of ECDHESA256KW, factored
// out of UnwrapCEK so a caller that only performs the ECDH agreement
// step itself (an HSM or KMS's raw key-agreement primitive, never
// handing this package a private key at all) can still recover the CEK
// through this package's own audited KDF/unwrap logic rather than
// reimplementing it.
func UnwrapCEKFromSharedSecret(alg fapi.KeyManagementAlgorithm, z, encryptedKey []byte) ([]byte, error) {
	switch alg {
	case fapi.ECDHESA256KW:
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
		return nil, fmt.Errorf("jwe: unsupported key management algorithm %v for shared-secret unwrap", alg)
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

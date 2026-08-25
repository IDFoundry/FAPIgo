package jwe

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
)

func generateRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	return priv
}

func generateECDHKey(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdh key: %v", err)
	}
	return priv
}

func TestEncryptDecryptRoundTripRSAOAEP256(t *testing.T) {
	priv := generateRSAKey(t)
	plaintext := []byte("the quick brown fox jumps over the lazy dog")

	compact, err := Encrypt(EncryptRequest{
		Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256GCM,
		RecipientKey: &priv.PublicKey, KeyID: "kid-1", ContentType: "JWT",
		Plaintext: plaintext,
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	result, err := Decrypt(context.Background(), DecryptRequest{
		Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256GCM,
		RecipientKey: priv, Compact: compact,
	})
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(result.Plaintext, plaintext) {
		t.Fatalf("Plaintext = %q, want %q", result.Plaintext, plaintext)
	}
	if result.Header.KeyID != "kid-1" || result.Header.ContentType != "JWT" {
		t.Fatalf("Header = %+v, want KeyID=kid-1 ContentType=JWT", result.Header)
	}
	if result.Header.EphemeralPublicKey != nil {
		t.Fatalf("Header.EphemeralPublicKey = %v, want nil for RSAOAEP256", result.Header.EphemeralPublicKey)
	}
}

func TestEncryptDecryptRoundTripECDHESA256KW(t *testing.T) {
	priv := generateECDHKey(t)
	plaintext := []byte("the quick brown fox jumps over the lazy dog")

	compact, err := Encrypt(EncryptRequest{
		Algorithm: fapi.ECDHESA256KW, Encryption: fapi.A256GCM,
		RecipientKey: priv.PublicKey(), KeyID: "kid-2",
		Plaintext: plaintext,
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	result, err := Decrypt(context.Background(), DecryptRequest{
		Algorithm: fapi.ECDHESA256KW, Encryption: fapi.A256GCM,
		RecipientKey: priv, Compact: compact,
	})
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(result.Plaintext, plaintext) {
		t.Fatalf("Plaintext = %q, want %q", result.Plaintext, plaintext)
	}
	if result.Header.KeyID != "kid-2" {
		t.Fatalf("Header.KeyID = %q, want kid-2", result.Header.KeyID)
	}
}

func TestEncryptDecryptRoundTripA256CBCHS512(t *testing.T) {
	priv := generateRSAKey(t)
	plaintext := []byte("the quick brown fox jumps over the lazy dog")

	compact, err := Encrypt(EncryptRequest{
		Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256CBCHS512,
		RecipientKey: &priv.PublicKey, KeyID: "kid-1", ContentType: "JWT",
		Plaintext: plaintext,
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	result, err := Decrypt(context.Background(), DecryptRequest{
		Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256CBCHS512,
		RecipientKey: priv, Compact: compact,
	})
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(result.Plaintext, plaintext) {
		t.Fatalf("Plaintext = %q, want %q", result.Plaintext, plaintext)
	}
	if result.Header.Encryption != fapi.A256CBCHS512 {
		t.Fatalf("Header.Encryption = %v, want A256CBCHS512", result.Header.Encryption)
	}
}

// TestEncryptDecryptRoundTripA256CBCHS512ECDHESA256KW confirms
// A256CBC-HS512 composes with either key-management algorithm, not
// just RSA-OAEP-256 — the two algorithm choices are orthogonal.
func TestEncryptDecryptRoundTripA256CBCHS512ECDHESA256KW(t *testing.T) {
	priv := generateECDHKey(t)
	plaintext := []byte("the quick brown fox jumps over the lazy dog")

	compact, err := Encrypt(EncryptRequest{
		Algorithm: fapi.ECDHESA256KW, Encryption: fapi.A256CBCHS512,
		RecipientKey: priv.PublicKey(), Plaintext: plaintext,
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	result, err := Decrypt(context.Background(), DecryptRequest{
		Algorithm: fapi.ECDHESA256KW, Encryption: fapi.A256CBCHS512,
		RecipientKey: priv, Compact: compact,
	})
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(result.Plaintext, plaintext) {
		t.Fatalf("Plaintext = %q, want %q", result.Plaintext, plaintext)
	}
}

// TestEncryptDecryptRoundTripA256CBCHS512EmptyPlaintext exercises the
// case where A256CBC-HS512's ciphertext is never actually empty (PKCS#7
// padding always emits at least one full block), unlike A256GCM's —
// see TestEncryptDecryptRoundTripEmptyPlaintext for that comparison
// case, and the segment-emptiness comment in Decrypt for why the parser
// stays permissive about it regardless of algorithm.
func TestEncryptDecryptRoundTripA256CBCHS512EmptyPlaintext(t *testing.T) {
	priv := generateRSAKey(t)
	compact, err := Encrypt(EncryptRequest{
		Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256CBCHS512,
		RecipientKey: &priv.PublicKey, Plaintext: []byte{},
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	parts := strings.Split(compact, ".")
	if parts[3] == "" {
		t.Fatalf("ciphertext segment is empty, want non-empty (PKCS#7 padding always adds a block)")
	}

	result, err := Decrypt(context.Background(), DecryptRequest{
		Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256CBCHS512,
		RecipientKey: priv, Compact: compact,
	})
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if len(result.Plaintext) != 0 {
		t.Fatalf("Plaintext = %q, want empty", result.Plaintext)
	}
}

// TestDecryptRejectsContentEncryptionMismatch confirms a JWE produced
// with one content-encryption algorithm is rejected when the caller
// requires the other — the "enc" analogue of
// TestDecryptRejectsAlgorithmMismatch, only exercisable now that a
// second ContentEncryptionAlgorithm actually exists.
func TestDecryptRejectsContentEncryptionMismatch(t *testing.T) {
	priv := generateRSAKey(t)
	compact, err := Encrypt(EncryptRequest{
		Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256CBCHS512,
		RecipientKey: &priv.PublicKey, Plaintext: []byte("secret"),
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := Decrypt(context.Background(), DecryptRequest{
		Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256GCM,
		RecipientKey: priv, Compact: compact,
	}); !errors.Is(err, ErrAlgorithmMismatch) {
		t.Fatalf("Decrypt(content encryption mismatch) = %v, want ErrAlgorithmMismatch", err)
	}
}

// TestDecryptRejectsTamperedTagA256CBCHS512 mirrors
// TestDecryptRejectsTamperedTag for the CBC-HMAC family, where tag
// verification is this package's own code (cbcHMACTag/hmac.Equal), not
// a stdlib AEAD call — the two paths are worth testing independently.
func TestDecryptRejectsTamperedTagA256CBCHS512(t *testing.T) {
	priv := generateRSAKey(t)
	compact, err := Encrypt(EncryptRequest{
		Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256CBCHS512,
		RecipientKey: &priv.PublicKey, Plaintext: []byte("secret"),
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	parts := strings.Split(compact, ".")
	tag, err := base64.RawURLEncoding.DecodeString(parts[4])
	if err != nil {
		t.Fatalf("decode tag: %v", err)
	}
	tag[0] ^= 0xFF
	parts[4] = base64.RawURLEncoding.EncodeToString(tag)
	tampered := strings.Join(parts, ".")

	if _, err := Decrypt(context.Background(), DecryptRequest{
		Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256CBCHS512,
		RecipientKey: priv, Compact: tampered,
	}); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("Decrypt(tampered tag) = %v, want ErrDecryptionFailed", err)
	}
}

func TestEncryptGeneratesFreshEphemeralKeyEachCall(t *testing.T) {
	priv := generateECDHKey(t)
	a, err := Encrypt(EncryptRequest{Algorithm: fapi.ECDHESA256KW, Encryption: fapi.A256GCM, RecipientKey: priv.PublicKey(), Plaintext: []byte("x")})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	b, err := Encrypt(EncryptRequest{Algorithm: fapi.ECDHESA256KW, Encryption: fapi.A256GCM, RecipientKey: priv.PublicKey(), Plaintext: []byte("x")})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if a == b {
		t.Fatalf("two Encrypt calls with the same plaintext produced identical output — ephemeral key and/or IV are not being freshly randomized")
	}
}

func TestDecryptRejectsWrongRSAKey(t *testing.T) {
	priv := generateRSAKey(t)
	other := generateRSAKey(t)
	compact, err := Encrypt(EncryptRequest{Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256GCM, RecipientKey: &priv.PublicKey, Plaintext: []byte("secret")})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := Decrypt(context.Background(), DecryptRequest{Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256GCM, RecipientKey: other, Compact: compact}); err == nil {
		t.Fatalf("Decrypt(wrong rsa key) = nil error, want error")
	}
}

func TestDecryptRejectsWrongECDHKey(t *testing.T) {
	priv := generateECDHKey(t)
	other := generateECDHKey(t)
	compact, err := Encrypt(EncryptRequest{Algorithm: fapi.ECDHESA256KW, Encryption: fapi.A256GCM, RecipientKey: priv.PublicKey(), Plaintext: []byte("secret")})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := Decrypt(context.Background(), DecryptRequest{Algorithm: fapi.ECDHESA256KW, Encryption: fapi.A256GCM, RecipientKey: other, Compact: compact}); err == nil {
		t.Fatalf("Decrypt(wrong ecdh key) = nil error, want error")
	}
}

// TestUnwrapCEKFromSharedSecretMatchesUnwrapCEK confirms the factored-out
// shared-secret path recovers exactly the CEK UnwrapCEK does when given
// the same private key — the two must never diverge, since a
// keys.Decrypter built over a backend that only performs ECDH agreement
// relies on this function alone to reach the same result an in-memory
// *ecdh.PrivateKey would via UnwrapCEK.
func TestUnwrapCEKFromSharedSecretMatchesUnwrapCEK(t *testing.T) {
	priv := generateECDHKey(t)
	compact, err := Encrypt(EncryptRequest{Algorithm: fapi.ECDHESA256KW, Encryption: fapi.A256GCM, RecipientKey: priv.PublicKey(), Plaintext: []byte("secret")})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	parts := strings.Split(compact, ".")
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	header, err := parseHeader(headerJSON)
	if err != nil {
		t.Fatalf("parseHeader: %v", err)
	}
	encryptedKey, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode encrypted key: %v", err)
	}

	want, err := UnwrapCEK(fapi.ECDHESA256KW, priv, encryptedKey, header.EphemeralPublicKey)
	if err != nil {
		t.Fatalf("UnwrapCEK: %v", err)
	}

	z, err := priv.ECDH(header.EphemeralPublicKey)
	if err != nil {
		t.Fatalf("ecdh: %v", err)
	}
	got, err := UnwrapCEKFromSharedSecret(fapi.ECDHESA256KW, z, encryptedKey)
	if err != nil {
		t.Fatalf("UnwrapCEKFromSharedSecret: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("UnwrapCEKFromSharedSecret = %x, want %x", got, want)
	}
}

func TestUnwrapCEKFromSharedSecretRejectsTamperedEncryptedKey(t *testing.T) {
	priv := generateECDHKey(t)
	compact, err := Encrypt(EncryptRequest{Algorithm: fapi.ECDHESA256KW, Encryption: fapi.A256GCM, RecipientKey: priv.PublicKey(), Plaintext: []byte("secret")})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	parts := strings.Split(compact, ".")
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	header, err := parseHeader(headerJSON)
	if err != nil {
		t.Fatalf("parseHeader: %v", err)
	}
	encryptedKey, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode encrypted key: %v", err)
	}
	encryptedKey[0] ^= 0xFF

	z, err := priv.ECDH(header.EphemeralPublicKey)
	if err != nil {
		t.Fatalf("ecdh: %v", err)
	}
	if _, err := UnwrapCEKFromSharedSecret(fapi.ECDHESA256KW, z, encryptedKey); err == nil {
		t.Fatal("UnwrapCEKFromSharedSecret(tampered encrypted key) = nil error, want error")
	}
}

func TestUnwrapCEKFromSharedSecretRejectsUnsupportedAlgorithm(t *testing.T) {
	if _, err := UnwrapCEKFromSharedSecret(fapi.RSAOAEP256, []byte("z"), []byte("wrapped")); err == nil {
		t.Fatal("UnwrapCEKFromSharedSecret(RSAOAEP256) = nil error, want error")
	}
}

func TestDecryptRejectsAlgorithmMismatch(t *testing.T) {
	priv := generateRSAKey(t)
	compact, err := Encrypt(EncryptRequest{Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256GCM, RecipientKey: &priv.PublicKey, Plaintext: []byte("secret")})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	// Caller expects ECDHESA256KW; the token actually says RSA-OAEP-256
	// — this must be rejected, never silently dispatched off the
	// header's own claim.
	ecdhPriv := generateECDHKey(t)
	if _, err := Decrypt(context.Background(), DecryptRequest{Algorithm: fapi.ECDHESA256KW, Encryption: fapi.A256GCM, RecipientKey: ecdhPriv, Compact: compact}); !errors.Is(err, ErrAlgorithmMismatch) {
		t.Fatalf("Decrypt(algorithm mismatch) = %v, want ErrAlgorithmMismatch", err)
	}
}

func TestDecryptRejectsTamperedCiphertext(t *testing.T) {
	priv := generateRSAKey(t)
	compact, err := Encrypt(EncryptRequest{Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256GCM, RecipientKey: &priv.PublicKey, Plaintext: []byte("secret")})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	parts := strings.Split(compact, ".")
	ciphertext, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		t.Fatalf("decode ciphertext: %v", err)
	}
	ciphertext[0] ^= 0xFF
	parts[3] = base64.RawURLEncoding.EncodeToString(ciphertext)
	tampered := strings.Join(parts, ".")

	if _, err := Decrypt(context.Background(), DecryptRequest{Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256GCM, RecipientKey: priv, Compact: tampered}); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("Decrypt(tampered ciphertext) = %v, want ErrDecryptionFailed", err)
	}
}

func TestDecryptRejectsTamperedTag(t *testing.T) {
	priv := generateRSAKey(t)
	compact, err := Encrypt(EncryptRequest{Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256GCM, RecipientKey: &priv.PublicKey, Plaintext: []byte("secret")})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	parts := strings.Split(compact, ".")
	tag, err := base64.RawURLEncoding.DecodeString(parts[4])
	if err != nil {
		t.Fatalf("decode tag: %v", err)
	}
	tag[0] ^= 0xFF
	parts[4] = base64.RawURLEncoding.EncodeToString(tag)
	tampered := strings.Join(parts, ".")

	if _, err := Decrypt(context.Background(), DecryptRequest{Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256GCM, RecipientKey: priv, Compact: tampered}); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("Decrypt(tampered tag) = %v, want ErrDecryptionFailed", err)
	}
}

func TestDecryptRejectsTamperedHeader(t *testing.T) {
	// The protected header is the AAD; changing it (even to something
	// that still parses) must invalidate the GCM tag, since the
	// original AAD is exactly the header bytes as transmitted.
	priv := generateRSAKey(t)
	compact, err := Encrypt(EncryptRequest{
		Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256GCM, RecipientKey: &priv.PublicKey,
		ContentType: "JWT", Plaintext: []byte("secret"),
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	parts := strings.Split(compact, ".")
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	tampered := strings.Replace(string(headerJSON), `"cty":"JWT"`, `"cty":"XXX"`, 1)
	if tampered == string(headerJSON) {
		t.Fatalf("test setup error: replacement did not change header")
	}
	parts[0] = base64.RawURLEncoding.EncodeToString([]byte(tampered))
	tamperedCompact := strings.Join(parts, ".")

	if _, err := Decrypt(context.Background(), DecryptRequest{Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256GCM, RecipientKey: priv, Compact: tamperedCompact}); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("Decrypt(tampered header) = %v, want ErrDecryptionFailed", err)
	}
}

func TestDecryptRejectsMalformedCompactSerialization(t *testing.T) {
	priv := generateRSAKey(t)
	cases := map[string]string{
		"too few segments":  "a.b.c.d",
		"too many segments": "a.b.c.d.e.f",
		"empty segment":     "a..c.d.e",
		"invalid base64":    "!!!.b.c.d.e",
	}
	for name, compact := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Decrypt(context.Background(), DecryptRequest{Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256GCM, RecipientKey: priv, Compact: compact}); !errors.Is(err, ErrMalformed) {
				t.Fatalf("Decrypt(%s) = %v, want ErrMalformed", name, err)
			}
		})
	}
}

// RSA-OAEP-256 must enforce the same minimum modulus size
// internal/jose's PS256 support already does — a small RSA key wrapping
// the CEK can be factored, defeating the encryption entirely.
func TestEncryptRejectsSmallRSAKey(t *testing.T) {
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate small rsa key: %v", err)
	}
	if _, err := Encrypt(EncryptRequest{Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256GCM, RecipientKey: &small.PublicKey, Plaintext: []byte("x")}); err == nil {
		t.Fatalf("Encrypt(1024-bit rsa key) = nil error, want error")
	}
}

func TestDecryptRejectsSmallRSAKey(t *testing.T) {
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate small rsa key: %v", err)
	}
	// Encrypted to a properly-sized key, then decrypted with a small
	// one of the right shape — this must fail on the key-size check,
	// not attempt DecryptOAEP with an undersized modulus.
	priv := generateRSAKey(t)
	compact, err := Encrypt(EncryptRequest{Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256GCM, RecipientKey: &priv.PublicKey, Plaintext: []byte("x")})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := Decrypt(context.Background(), DecryptRequest{Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256GCM, RecipientKey: small, Compact: compact}); err == nil {
		t.Fatalf("Decrypt(1024-bit rsa key) = nil error, want error")
	}
}

func TestEncryptRejectsWrongKeyType(t *testing.T) {
	rsaPriv := generateRSAKey(t)
	if _, err := Encrypt(EncryptRequest{Algorithm: fapi.ECDHESA256KW, Encryption: fapi.A256GCM, RecipientKey: &rsaPriv.PublicKey, Plaintext: []byte("x")}); err == nil {
		t.Fatalf("Encrypt(ECDHESA256KW, rsa key) = nil error, want error")
	}
	ecdhPriv := generateECDHKey(t)
	if _, err := Encrypt(EncryptRequest{Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256GCM, RecipientKey: ecdhPriv.PublicKey(), Plaintext: []byte("x")}); err == nil {
		t.Fatalf("Encrypt(RSAOAEP256, ecdh key) = nil error, want error")
	}
}

func TestEncryptRejectsInvalidAlgorithm(t *testing.T) {
	priv := generateRSAKey(t)
	if _, err := Encrypt(EncryptRequest{Encryption: fapi.A256GCM, RecipientKey: &priv.PublicKey, Plaintext: []byte("x")}); err == nil {
		t.Fatalf("Encrypt(zero Algorithm) = nil error, want error")
	}
}

func TestEncryptRejectsInvalidEncryption(t *testing.T) {
	priv := generateRSAKey(t)
	if _, err := Encrypt(EncryptRequest{Algorithm: fapi.RSAOAEP256, RecipientKey: &priv.PublicKey, Plaintext: []byte("x")}); err == nil {
		t.Fatalf("Encrypt(zero Encryption) = nil error, want error")
	}
}

// fakeUnwrapper stands in for a KeyManager-backed Unwrapper that never
// exposes its private key to this package — it holds the real key
// itself and delegates to the exported UnwrapCEK, the same logic
// Decrypt's own concrete-key path uses, so this test proves dispatch
// correctness, not a second crypto implementation.
type fakeUnwrapper struct {
	alg fapi.KeyManagementAlgorithm
	key any
	// ctxSeen records the ctx UnwrapCEK was actually called with, so the
	// test can confirm Decrypt threads its own ctx through rather than
	// silently substituting context.Background().
	ctxSeen context.Context
	// keyIDSeen records the keyID UnwrapCEK was actually called with, so
	// a test can confirm Decrypt forwards the header's own "kid" rather
	// than dropping it.
	keyIDSeen string
}

func (f *fakeUnwrapper) UnwrapCEK(ctx context.Context, alg fapi.KeyManagementAlgorithm, keyID string, encryptedKey []byte, epk *ecdh.PublicKey) ([]byte, error) {
	f.ctxSeen = ctx
	f.keyIDSeen = keyID
	if alg != f.alg {
		return nil, fmt.Errorf("fakeUnwrapper: alg = %v, want %v", alg, f.alg)
	}
	return UnwrapCEK(alg, f.key, encryptedKey, epk)
}

func TestDecryptDispatchesToUnwrapper(t *testing.T) {
	priv := generateRSAKey(t)
	plaintext := []byte("secret")
	compact, err := Encrypt(EncryptRequest{Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256GCM, RecipientKey: &priv.PublicKey, Plaintext: plaintext})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	unwrapper := &fakeUnwrapper{alg: fapi.RSAOAEP256, key: priv}
	type ctxKey struct{}
	ctx := context.WithValue(context.Background(), ctxKey{}, "marker")
	result, err := Decrypt(ctx, DecryptRequest{Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256GCM, RecipientKey: unwrapper, Compact: compact})
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(result.Plaintext, plaintext) {
		t.Fatalf("Plaintext = %q, want %q", result.Plaintext, plaintext)
	}
	if unwrapper.ctxSeen == nil || unwrapper.ctxSeen.Value(ctxKey{}) != "marker" {
		t.Fatalf("Unwrapper did not receive Decrypt's own ctx")
	}
}

// TestDecryptForwardsHeaderKeyIDToUnwrapper confirms Decrypt passes the
// JWE header's own "kid" through to Unwrapper rather than discarding
// it — the wiring an Unwrapper backed by more than one registered key
// (e.g. mid-rotation) needs to select the right one.
func TestDecryptForwardsHeaderKeyIDToUnwrapper(t *testing.T) {
	priv := generateRSAKey(t)
	plaintext := []byte("secret")
	compact, err := Encrypt(EncryptRequest{
		Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256GCM, RecipientKey: &priv.PublicKey,
		KeyID: "rotation-kid-2", Plaintext: plaintext,
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	unwrapper := &fakeUnwrapper{alg: fapi.RSAOAEP256, key: priv}
	if _, err := Decrypt(context.Background(), DecryptRequest{Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256GCM, RecipientKey: unwrapper, Compact: compact}); err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if unwrapper.keyIDSeen != "rotation-kid-2" {
		t.Fatalf("keyIDSeen = %q, want %q", unwrapper.keyIDSeen, "rotation-kid-2")
	}
}

func TestDecryptWrapsUnwrapperError(t *testing.T) {
	priv := generateRSAKey(t)
	compact, err := Encrypt(EncryptRequest{Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256GCM, RecipientKey: &priv.PublicKey, Plaintext: []byte("secret")})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	other := generateRSAKey(t)
	unwrapper := &fakeUnwrapper{alg: fapi.RSAOAEP256, key: other}
	if _, err := Decrypt(context.Background(), DecryptRequest{Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256GCM, RecipientKey: unwrapper, Compact: compact}); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("Decrypt(unwrapper with wrong key) = %v, want ErrDecryptionFailed", err)
	}
}

func TestEncryptDecryptRoundTripEmptyPlaintext(t *testing.T) {
	priv := generateRSAKey(t)
	compact, err := Encrypt(EncryptRequest{Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256GCM, RecipientKey: &priv.PublicKey, Plaintext: []byte{}})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	result, err := Decrypt(context.Background(), DecryptRequest{Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256GCM, RecipientKey: priv, Compact: compact})
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if len(result.Plaintext) != 0 {
		t.Fatalf("Plaintext = %q, want empty", result.Plaintext)
	}
}

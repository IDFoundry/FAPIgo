package ephemeral

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rsa"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jwe"
	"github.com/idfoundry/fapigo/keys"
)

// testUnwrapper adapts a keys.Decrypter (request-struct shaped) to
// jwe.Unwrapper (flat-argument shaped) for a fixed purpose — the same
// kind of small bridge client's own production code will need in front
// of a real KeyManager; kept local to this test since Phase 2 only
// needs to prove the two interfaces are compatible, not ship the glue.
type testUnwrapper struct {
	d       keys.Decrypter
	purpose keys.DecryptionPurpose
}

func (u testUnwrapper) UnwrapCEK(ctx context.Context, alg fapi.KeyManagementAlgorithm, encryptedKey []byte, epk *ecdh.PublicKey) ([]byte, error) {
	return u.d.UnwrapContentEncryptionKey(ctx, keys.UnwrapRequest{
		Purpose: u.purpose, Algorithm: alg, EncryptedKey: encryptedKey, EphemeralPublicKey: epk,
	})
}

func TestKeyManagerDecrypterRoundTripRSAOAEP256(t *testing.T) {
	m, err := NewKeyManagerWithDecryption(nil, map[keys.DecryptionPurpose]fapi.KeyManagementAlgorithm{
		keys.IDTokenDecryption: fapi.RSAOAEP256,
	})
	if err != nil {
		t.Fatalf("NewKeyManagerWithDecryption: %v", err)
	}

	info, err := m.EncryptionPublicKey(context.Background(), keys.IDTokenDecryption, fapi.RSAOAEP256)
	if err != nil {
		t.Fatalf("EncryptionPublicKey: %v", err)
	}
	pub, ok := info.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("PublicKey type = %T, want *rsa.PublicKey", info.PublicKey)
	}

	plaintext := []byte("nested jwt goes here")
	compact, err := jwe.Encrypt(jwe.EncryptRequest{
		Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256GCM, RecipientKey: pub, Plaintext: plaintext,
	})
	if err != nil {
		t.Fatalf("jwe.Encrypt: %v", err)
	}

	unwrapper := testUnwrapper{d: m, purpose: keys.IDTokenDecryption}
	result, err := jwe.Decrypt(context.Background(), jwe.DecryptRequest{
		Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256GCM, RecipientKey: unwrapper, Compact: compact,
	})
	if err != nil {
		t.Fatalf("jwe.Decrypt: %v", err)
	}
	if !bytes.Equal(result.Plaintext, plaintext) {
		t.Fatalf("Plaintext = %q, want %q", result.Plaintext, plaintext)
	}
}

func TestKeyManagerDecrypterRoundTripECDHESA256KW(t *testing.T) {
	m, err := NewKeyManagerWithDecryption(nil, map[keys.DecryptionPurpose]fapi.KeyManagementAlgorithm{
		keys.IDTokenDecryption: fapi.ECDHESA256KW,
	})
	if err != nil {
		t.Fatalf("NewKeyManagerWithDecryption: %v", err)
	}

	info, err := m.EncryptionPublicKey(context.Background(), keys.IDTokenDecryption, fapi.ECDHESA256KW)
	if err != nil {
		t.Fatalf("EncryptionPublicKey: %v", err)
	}
	pub, ok := info.PublicKey.(*ecdh.PublicKey)
	if !ok {
		t.Fatalf("PublicKey type = %T, want *ecdh.PublicKey", info.PublicKey)
	}
	if info.KeyID == "" {
		t.Fatal("EncryptionPublicKey returned an empty KeyID")
	}

	plaintext := []byte("nested jwt goes here")
	compact, err := jwe.Encrypt(jwe.EncryptRequest{
		Algorithm: fapi.ECDHESA256KW, Encryption: fapi.A256GCM, RecipientKey: pub, Plaintext: plaintext,
	})
	if err != nil {
		t.Fatalf("jwe.Encrypt: %v", err)
	}

	unwrapper := testUnwrapper{d: m, purpose: keys.IDTokenDecryption}
	result, err := jwe.Decrypt(context.Background(), jwe.DecryptRequest{
		Algorithm: fapi.ECDHESA256KW, Encryption: fapi.A256GCM, RecipientKey: unwrapper, Compact: compact,
	})
	if err != nil {
		t.Fatalf("jwe.Decrypt: %v", err)
	}
	if !bytes.Equal(result.Plaintext, plaintext) {
		t.Fatalf("Plaintext = %q, want %q", result.Plaintext, plaintext)
	}
}

func TestKeyManagerRejectsUnconfiguredDecryptionPurpose(t *testing.T) {
	m, err := NewKeyManagerWithDecryption(nil, map[keys.DecryptionPurpose]fapi.KeyManagementAlgorithm{
		keys.IDTokenDecryption: fapi.RSAOAEP256,
	})
	if err != nil {
		t.Fatalf("NewKeyManagerWithDecryption: %v", err)
	}
	const unconfigured keys.DecryptionPurpose = 99
	if _, err := m.UnwrapContentEncryptionKey(context.Background(), keys.UnwrapRequest{Purpose: unconfigured, Algorithm: fapi.RSAOAEP256}); err == nil {
		t.Fatal("UnwrapContentEncryptionKey(unconfigured purpose) = nil error, want error")
	}
	if _, err := m.EncryptionPublicKey(context.Background(), unconfigured, fapi.RSAOAEP256); err == nil {
		t.Fatal("EncryptionPublicKey(unconfigured purpose) = nil error, want error")
	}
}

// A *KeyManager built via plain NewKeyManager (no decryption purposes)
// must fail closed on Decrypter calls rather than panic on a nil map —
// most callers never use decryption at all.
func TestKeyManagerWithoutDecryptionRejectsDecrypterCalls(t *testing.T) {
	m, err := NewKeyManager(map[keys.SigningPurpose]fapi.SignatureAlgorithm{keys.AccessTokenSigning: fapi.ES256})
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}
	if _, err := m.UnwrapContentEncryptionKey(context.Background(), keys.UnwrapRequest{Purpose: keys.IDTokenDecryption, Algorithm: fapi.RSAOAEP256}); err == nil {
		t.Fatal("UnwrapContentEncryptionKey(no decryption configured) = nil error, want error")
	}
	if _, err := m.EncryptionPublicKey(context.Background(), keys.IDTokenDecryption, fapi.RSAOAEP256); err == nil {
		t.Fatal("EncryptionPublicKey(no decryption configured) = nil error, want error")
	}
}

// NewKeyManagerWithDecryption's signing half must behave identically to
// plain NewKeyManager — decryption support is additive, not a
// replacement.
func TestKeyManagerWithDecryptionStillSigns(t *testing.T) {
	m, err := NewKeyManagerWithDecryption(
		map[keys.SigningPurpose]fapi.SignatureAlgorithm{keys.AccessTokenSigning: fapi.ES256},
		map[keys.DecryptionPurpose]fapi.KeyManagementAlgorithm{keys.IDTokenDecryption: fapi.RSAOAEP256},
	)
	if err != nil {
		t.Fatalf("NewKeyManagerWithDecryption: %v", err)
	}
	if _, err := m.PublicKey(context.Background(), keys.AccessTokenSigning, fapi.ES256); err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
}

func TestNewKeyManagerWithDecryptionRejectsUnsupportedAlgorithm(t *testing.T) {
	if _, err := NewKeyManagerWithDecryption(nil, map[keys.DecryptionPurpose]fapi.KeyManagementAlgorithm{
		keys.IDTokenDecryption: fapi.KeyManagementAlgorithm(0),
	}); err == nil {
		t.Fatal("NewKeyManagerWithDecryption(unsupported algorithm) = nil error, want error")
	}
}

package keys_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jwe"
	"github.com/idfoundry/fapigo/keys"
)

// testUnwrapper adapts a keys.Decrypter (request-struct shaped) to
// jwe.Unwrapper (flat-argument shaped) for a fixed purpose — the same
// bridge client's own production code (and keys/ephemeral's own tests)
// use in front of a real Decrypter.
type testUnwrapper struct {
	d       keys.Decrypter
	purpose keys.DecryptionPurpose
}

func (u testUnwrapper) UnwrapCEK(ctx context.Context, alg fapi.KeyManagementAlgorithm, keyID string, encryptedKey []byte, epk *ecdh.PublicKey) ([]byte, error) {
	return u.d.UnwrapContentEncryptionKey(ctx, keys.UnwrapRequest{
		Purpose: u.purpose, Algorithm: alg, KeyID: keyID, EncryptedKey: encryptedKey, EphemeralPublicKey: epk,
	})
}

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

// TestNewDecrypterRoundTripECDHESA256KW proves a Decrypter built purely
// over ECDHAgreer — the capability an HSM's CKM_ECDH1_DERIVE or AWS
// KMS's DeriveSharedSecret exposes — recovers a real JWE's plaintext
// without this package ever seeing the private key directly (it only
// ever calls AgreeSharedSecret).
func TestNewDecrypterRoundTripECDHESA256KW(t *testing.T) {
	priv := generateECDHKey(t)
	backend, err := keys.NewInMemoryECDH(priv, "test-ecdh-key")
	if err != nil {
		t.Fatalf("NewInMemoryECDH: %v", err)
	}
	dec, err := keys.NewSingleKeyDecrypter(backend)
	if err != nil {
		t.Fatalf("NewSingleKeyDecrypter: %v", err)
	}

	info, err := dec.EncryptionPublicKey(context.Background(), keys.IDTokenDecryption, fapi.ECDHESA256KW)
	if err != nil {
		t.Fatalf("EncryptionPublicKey: %v", err)
	}
	pub, ok := info.PublicKey.(*ecdh.PublicKey)
	if !ok {
		t.Fatalf("PublicKey type = %T, want *ecdh.PublicKey", info.PublicKey)
	}
	if info.KeyID != "test-ecdh-key" {
		t.Fatalf("KeyID = %q, want %q", info.KeyID, "test-ecdh-key")
	}

	plaintext := []byte("nested jwt goes here")
	compact, err := jwe.Encrypt(jwe.EncryptRequest{
		Algorithm: fapi.ECDHESA256KW, Encryption: fapi.A256GCM, RecipientKey: pub, Plaintext: plaintext,
	})
	if err != nil {
		t.Fatalf("jwe.Encrypt: %v", err)
	}

	result, err := jwe.Decrypt(context.Background(), jwe.DecryptRequest{
		Algorithm: fapi.ECDHESA256KW, Encryption: fapi.A256GCM,
		RecipientKey: testUnwrapper{d: dec, purpose: keys.IDTokenDecryption}, Compact: compact,
	})
	if err != nil {
		t.Fatalf("jwe.Decrypt: %v", err)
	}
	if !bytes.Equal(result.Plaintext, plaintext) {
		t.Fatalf("Plaintext = %q, want %q", result.Plaintext, plaintext)
	}
}

// TestNewDecrypterRoundTripRSAOAEP256 proves a Decrypter built purely
// over KeyDecrypter — the capability every major managed KMS exposes
// non-exportably — recovers a real JWE's plaintext.
func TestNewDecrypterRoundTripRSAOAEP256(t *testing.T) {
	priv := generateRSAKey(t)
	backend, err := keys.NewInMemoryRSA(priv, "test-rsa-key")
	if err != nil {
		t.Fatalf("NewInMemoryRSA: %v", err)
	}
	dec, err := keys.NewSingleKeyDecrypter(backend)
	if err != nil {
		t.Fatalf("NewSingleKeyDecrypter: %v", err)
	}

	info, err := dec.EncryptionPublicKey(context.Background(), keys.UserInfoDecryption, fapi.RSAOAEP256)
	if err != nil {
		t.Fatalf("EncryptionPublicKey: %v", err)
	}
	pub, ok := info.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("PublicKey type = %T, want *rsa.PublicKey", info.PublicKey)
	}

	plaintext := []byte("userinfo jws goes here")
	compact, err := jwe.Encrypt(jwe.EncryptRequest{
		Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256CBCHS512, RecipientKey: pub, Plaintext: plaintext,
	})
	if err != nil {
		t.Fatalf("jwe.Encrypt: %v", err)
	}

	result, err := jwe.Decrypt(context.Background(), jwe.DecryptRequest{
		Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256CBCHS512,
		RecipientKey: testUnwrapper{d: dec, purpose: keys.UserInfoDecryption}, Compact: compact,
	})
	if err != nil {
		t.Fatalf("jwe.Decrypt: %v", err)
	}
	if !bytes.Equal(result.Plaintext, plaintext) {
		t.Fatalf("Plaintext = %q, want %q", result.Plaintext, plaintext)
	}
}

// TestNewDecrypterDistinctKeyPerPurpose confirms one Decrypter can
// serve a different key for IDTokenDecryption than for
// UserInfoDecryption — NewDecrypter, unlike NewSingleKeyDecrypter, must
// not collapse the two.
func TestNewDecrypterDistinctKeyPerPurpose(t *testing.T) {
	idTokenBackend, err := keys.NewInMemoryRSA(generateRSAKey(t), "id-token-key")
	if err != nil {
		t.Fatalf("NewInMemoryRSA: %v", err)
	}
	userInfoBackend, err := keys.NewInMemoryRSA(generateRSAKey(t), "userinfo-key")
	if err != nil {
		t.Fatalf("NewInMemoryRSA: %v", err)
	}
	dec, err := keys.NewDecrypter(map[keys.DecryptionPurpose]keys.RecipientKey{
		keys.IDTokenDecryption:  idTokenBackend,
		keys.UserInfoDecryption: userInfoBackend,
	})
	if err != nil {
		t.Fatalf("NewDecrypter: %v", err)
	}

	idInfo, err := dec.EncryptionPublicKey(context.Background(), keys.IDTokenDecryption, fapi.RSAOAEP256)
	if err != nil {
		t.Fatalf("EncryptionPublicKey(IDTokenDecryption): %v", err)
	}
	userInfoInfo, err := dec.EncryptionPublicKey(context.Background(), keys.UserInfoDecryption, fapi.RSAOAEP256)
	if err != nil {
		t.Fatalf("EncryptionPublicKey(UserInfoDecryption): %v", err)
	}
	if idInfo.KeyID != "id-token-key" || userInfoInfo.KeyID != "userinfo-key" {
		t.Fatalf("KeyIDs = %q, %q, want distinct id-token-key/userinfo-key", idInfo.KeyID, userInfoInfo.KeyID)
	}

	// A JWE wrapped to the UserInfo key must not decrypt as an ID token:
	// UnwrapContentEncryptionKey(IDTokenDecryption) must use the
	// ID-token backend, not fall back to whichever key happens to be
	// registered.
	userInfoPub, ok := userInfoInfo.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("PublicKey type = %T, want *rsa.PublicKey", userInfoInfo.PublicKey)
	}
	compact, err := jwe.Encrypt(jwe.EncryptRequest{
		Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256GCM, RecipientKey: userInfoPub, Plaintext: []byte("x"),
	})
	if err != nil {
		t.Fatalf("jwe.Encrypt: %v", err)
	}
	if _, err := jwe.Decrypt(context.Background(), jwe.DecryptRequest{
		Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256GCM,
		RecipientKey: testUnwrapper{d: dec, purpose: keys.IDTokenDecryption}, Compact: compact,
	}); err == nil {
		t.Fatal("Decrypt(userinfo-wrapped JWE, as IDTokenDecryption) = nil error, want error")
	}
}

func TestNewDecrypterRejectsEmptyBackends(t *testing.T) {
	if _, err := keys.NewDecrypter(nil); err == nil {
		t.Fatal("NewDecrypter(nil) = nil error, want error")
	}
	if _, err := keys.NewDecrypter(map[keys.DecryptionPurpose]keys.RecipientKey{}); err == nil {
		t.Fatal("NewDecrypter(empty map) = nil error, want error")
	}
}

func TestNewDecrypterRejectsNilBackend(t *testing.T) {
	if _, err := keys.NewDecrypter(map[keys.DecryptionPurpose]keys.RecipientKey{
		keys.IDTokenDecryption: nil,
	}); err == nil {
		t.Fatal("NewDecrypter(nil backend) = nil error, want error")
	}
}

// bareRecipientKey implements only RecipientKey — neither ECDHAgreer
// nor KeyDecrypter — the case NewDecrypter must reject at construction
// rather than fail confusingly on the first request.
type bareRecipientKey struct{}

func (bareRecipientKey) PublicKey(context.Context) (keys.PublicKeyInfo, error) {
	return keys.PublicKeyInfo{}, nil
}

func TestNewDecrypterRejectsBackendWithNoCapability(t *testing.T) {
	if _, err := keys.NewDecrypter(map[keys.DecryptionPurpose]keys.RecipientKey{
		keys.IDTokenDecryption: bareRecipientKey{},
	}); err == nil {
		t.Fatal("NewDecrypter(backend with no capability) = nil error, want error")
	}
}

func TestNewDecrypterUnwrapRejectsUnconfiguredPurpose(t *testing.T) {
	backend, err := keys.NewInMemoryRSA(generateRSAKey(t), "kid")
	if err != nil {
		t.Fatalf("NewInMemoryRSA: %v", err)
	}
	dec, err := keys.NewDecrypter(map[keys.DecryptionPurpose]keys.RecipientKey{keys.IDTokenDecryption: backend})
	if err != nil {
		t.Fatalf("NewDecrypter: %v", err)
	}
	if _, err := dec.UnwrapContentEncryptionKey(context.Background(), keys.UnwrapRequest{
		Purpose: keys.UserInfoDecryption, Algorithm: fapi.RSAOAEP256,
	}); err == nil {
		t.Fatal("UnwrapContentEncryptionKey(unconfigured purpose) = nil error, want error")
	}
	if _, err := dec.EncryptionPublicKey(context.Background(), keys.UserInfoDecryption, fapi.RSAOAEP256); err == nil {
		t.Fatal("EncryptionPublicKey(unconfigured purpose) = nil error, want error")
	}
}

// TestNewDecrypterRejectsMismatchedAlgorithm confirms an ECDH-only
// backend produces a clear error for an RSAOAEP256 request (and vice
// versa) rather than a panic or a misleading one.
func TestNewDecrypterRejectsMismatchedAlgorithm(t *testing.T) {
	ecdhBackend, err := keys.NewInMemoryECDH(generateECDHKey(t), "kid")
	if err != nil {
		t.Fatalf("NewInMemoryECDH: %v", err)
	}
	dec, err := keys.NewSingleKeyDecrypter(ecdhBackend)
	if err != nil {
		t.Fatalf("NewSingleKeyDecrypter: %v", err)
	}
	if _, err := dec.UnwrapContentEncryptionKey(context.Background(), keys.UnwrapRequest{
		Purpose: keys.IDTokenDecryption, Algorithm: fapi.RSAOAEP256, EncryptedKey: []byte("wrapped"),
	}); err == nil {
		t.Fatal("UnwrapContentEncryptionKey(RSAOAEP256, ecdh-only backend) = nil error, want error")
	}

	rsaBackend, err := keys.NewInMemoryRSA(generateRSAKey(t), "kid")
	if err != nil {
		t.Fatalf("NewInMemoryRSA: %v", err)
	}
	dec, err = keys.NewSingleKeyDecrypter(rsaBackend)
	if err != nil {
		t.Fatalf("NewSingleKeyDecrypter: %v", err)
	}
	if _, err := dec.UnwrapContentEncryptionKey(context.Background(), keys.UnwrapRequest{
		Purpose: keys.IDTokenDecryption, Algorithm: fapi.ECDHESA256KW,
		EncryptedKey: []byte("wrapped"), EphemeralPublicKey: generateECDHKey(t).PublicKey(),
	}); err == nil {
		t.Fatal("UnwrapContentEncryptionKey(ECDHESA256KW, rsa-only backend) = nil error, want error")
	}
}

func TestNewDecrypterUnwrapRejectsMissingEphemeralPublicKey(t *testing.T) {
	backend, err := keys.NewInMemoryECDH(generateECDHKey(t), "kid")
	if err != nil {
		t.Fatalf("NewInMemoryECDH: %v", err)
	}
	dec, err := keys.NewSingleKeyDecrypter(backend)
	if err != nil {
		t.Fatalf("NewSingleKeyDecrypter: %v", err)
	}
	if _, err := dec.UnwrapContentEncryptionKey(context.Background(), keys.UnwrapRequest{
		Purpose: keys.IDTokenDecryption, Algorithm: fapi.ECDHESA256KW, EncryptedKey: []byte("wrapped"),
	}); err == nil {
		t.Fatal("UnwrapContentEncryptionKey(missing epk) = nil error, want error")
	}
}

// multiKeyRSA is a KeyDecrypter fake holding more than one RSA key,
// selecting among them by the keyID DecryptKey receives — the shape a
// real backend would take to service decryption through a key
// rotation's overlap window, proving the kid threaded through
// UnwrapRequest/Unwrapper (see internal/jwe's own
// TestDecryptForwardsHeaderKeyIDToUnwrapper) actually reaches the point
// where it matters: selecting which of several registered keys to use.
type multiKeyRSA struct {
	keys      map[string]*rsa.PrivateKey
	activeKID string
}

func (m *multiKeyRSA) PublicKey(context.Context) (keys.PublicKeyInfo, error) {
	return keys.PublicKeyInfo{KeyID: m.activeKID, PublicKey: &m.keys[m.activeKID].PublicKey}, nil
}

func (m *multiKeyRSA) DecryptKey(_ context.Context, keyID string, alg fapi.KeyManagementAlgorithm, wrapped []byte) ([]byte, error) {
	if alg != fapi.RSAOAEP256 {
		return nil, fmt.Errorf("multiKeyRSA: unsupported algorithm %v", alg)
	}
	priv, ok := m.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("multiKeyRSA: no key registered for kid %q", keyID)
	}
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, wrapped, nil)
}

// TestNewDecrypterServicesOutgoingKeyDuringRotation proves the actual
// rotation scenario Part B exists for: a JWE encrypted under a key that
// has since been rotated out (the AS was still using a cached JWKS
// entry, or simply hadn't caught up yet) still decrypts correctly,
// because the JWE's own "kid" reaches the backend and it still holds
// that key alongside the new one.
func TestNewDecrypterServicesOutgoingKeyDuringRotation(t *testing.T) {
	outgoing, newest := generateRSAKey(t), generateRSAKey(t)
	backend := &multiKeyRSA{
		keys:      map[string]*rsa.PrivateKey{"outgoing-kid": outgoing, "newest-kid": newest},
		activeKID: "newest-kid",
	}
	dec, err := keys.NewSingleKeyDecrypter(backend)
	if err != nil {
		t.Fatalf("NewSingleKeyDecrypter: %v", err)
	}
	unwrapper := testUnwrapper{d: dec, purpose: keys.IDTokenDecryption}

	// A JWE encrypted to the outgoing key, carrying its kid — as if it
	// were encrypted before, or during, the rotation.
	plaintext := []byte("issued just before rotation completed")
	compact, err := jwe.Encrypt(jwe.EncryptRequest{
		Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256GCM,
		RecipientKey: &outgoing.PublicKey, KeyID: "outgoing-kid", Plaintext: plaintext,
	})
	if err != nil {
		t.Fatalf("jwe.Encrypt: %v", err)
	}
	result, err := jwe.Decrypt(context.Background(), jwe.DecryptRequest{
		Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256GCM, RecipientKey: unwrapper, Compact: compact,
	})
	if err != nil {
		t.Fatalf("jwe.Decrypt(outgoing key JWE): %v", err)
	}
	if !bytes.Equal(result.Plaintext, plaintext) {
		t.Fatalf("Plaintext = %q, want %q", result.Plaintext, plaintext)
	}

	// The newest key must still work too — rotation doesn't drop the
	// forward path.
	compact2, err := jwe.Encrypt(jwe.EncryptRequest{
		Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256GCM,
		RecipientKey: &newest.PublicKey, KeyID: "newest-kid", Plaintext: plaintext,
	})
	if err != nil {
		t.Fatalf("jwe.Encrypt: %v", err)
	}
	if _, err := jwe.Decrypt(context.Background(), jwe.DecryptRequest{
		Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256GCM, RecipientKey: unwrapper, Compact: compact2,
	}); err != nil {
		t.Fatalf("jwe.Decrypt(newest key JWE): %v", err)
	}
}

package ephemeral

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jwe"
	"github.com/idfoundry/fapigo/keys"
)

// decryptionKeys holds this KeyManager's decryption-purpose keys,
// separate from the signing-purpose map NewKeyManager populates —
// decryption support is opt-in via NewKeyManagerWithDecryption, so a
// plain NewKeyManager (the common case) never allocates it.
type decryptionKeys struct {
	keys map[keys.DecryptionPurpose]crypto.PrivateKey
	kid  map[keys.DecryptionPurpose]string
}

// NewKeyManagerWithDecryption is NewKeyManager plus one decryption key
// per purpose in decryptionPurposes, sized for the paired algorithm
// (RSA-2048 for RSAOAEP256, ECDH P-256 for ECDHESA256KW — the only two
// algorithms this module supports). The returned *KeyManager implements
// both keys.KeyManager and keys.Decrypter.
func NewKeyManagerWithDecryption(
	signingPurposes map[keys.SigningPurpose]fapi.SignatureAlgorithm,
	decryptionPurposes map[keys.DecryptionPurpose]fapi.KeyManagementAlgorithm,
) (*KeyManager, error) {
	m, err := NewKeyManager(signingPurposes)
	if err != nil {
		return nil, err
	}
	dk := &decryptionKeys{
		keys: make(map[keys.DecryptionPurpose]crypto.PrivateKey, len(decryptionPurposes)),
		kid:  make(map[keys.DecryptionPurpose]string, len(decryptionPurposes)),
	}
	for purpose, alg := range decryptionPurposes {
		priv, err := generateDecryptionKey(alg)
		if err != nil {
			return nil, fmt.Errorf("generate decryption key for purpose %v: %w", purpose, err)
		}
		dk.keys[purpose] = priv
		dk.kid[purpose] = fmt.Sprintf("ephemeral-dec-%d-%s", purpose, alg.String())
	}
	m.decryption = dk
	return m, nil
}

func generateDecryptionKey(alg fapi.KeyManagementAlgorithm) (crypto.PrivateKey, error) {
	switch alg {
	case fapi.RSAOAEP256:
		return rsa.GenerateKey(rand.Reader, 2048)
	case fapi.ECDHESA256KW:
		return ecdh.P256().GenerateKey(rand.Reader)
	default:
		return nil, fmt.Errorf("unsupported algorithm %v", alg)
	}
}

func publicKeyOf(priv crypto.PrivateKey) (crypto.PublicKey, error) {
	switch key := priv.(type) {
	case *rsa.PrivateKey:
		return &key.PublicKey, nil
	case *ecdh.PrivateKey:
		return key.PublicKey(), nil
	default:
		return nil, fmt.Errorf("ephemeral: unsupported decryption key type %T", priv)
	}
}

// UnwrapContentEncryptionKey implements keys.Decrypter. The private key
// never leaves this method — UnwrapCEK performs the RSA-OAEP-256 or
// ECDH-ES+A256KW recovery internally and returns only the resulting CEK
// bytes, the same "never hand back the private key" contract Sign
// already honors for signing purposes.
func (m *KeyManager) UnwrapContentEncryptionKey(_ context.Context, req keys.UnwrapRequest) ([]byte, error) {
	if m.decryption == nil {
		return nil, fmt.Errorf("ephemeral: no decryption keys configured")
	}
	m.mu.Lock()
	priv, ok := m.decryption.keys[req.Purpose]
	m.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("ephemeral: no key for decryption purpose %v", req.Purpose)
	}
	return jwe.UnwrapCEK(req.Algorithm, priv, req.EncryptedKey, req.EphemeralPublicKey)
}

// EncryptionPublicKey implements keys.Decrypter.
func (m *KeyManager) EncryptionPublicKey(_ context.Context, purpose keys.DecryptionPurpose, _ fapi.KeyManagementAlgorithm) (keys.PublicKeyInfo, error) {
	if m.decryption == nil {
		return keys.PublicKeyInfo{}, fmt.Errorf("ephemeral: no decryption keys configured")
	}
	m.mu.Lock()
	priv, ok := m.decryption.keys[purpose]
	kid := m.decryption.kid[purpose]
	m.mu.Unlock()
	if !ok {
		return keys.PublicKeyInfo{}, fmt.Errorf("ephemeral: no key for decryption purpose %v", purpose)
	}
	pub, err := publicKeyOf(priv)
	if err != nil {
		return keys.PublicKeyInfo{}, err
	}
	return keys.PublicKeyInfo{KeyID: kid, PublicKey: pub}, nil
}

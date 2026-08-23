package ephemeral

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"sync"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
)

// KeyManager is a keys.KeyManager backed by fresh in-memory keys
// generated once at construction, one per active signing purpose. See
// the package doc comment for why this is development/testing only.
//
// It also implements keys.Decrypter when constructed via
// NewKeyManagerWithDecryption (see decrypter.go) — decryption is opt-in
// since most callers never need it, and decryption is not merely an
// addition to keys.KeyManager (the underlying key types and use cases
// differ), so plain NewKeyManager leaves the decryption field nil.
type KeyManager struct {
	mu         sync.Mutex
	keys       map[keys.SigningPurpose]crypto.Signer
	kid        map[keys.SigningPurpose]string
	decryption *decryptionKeys
}

// NewKeyManager generates one key per purpose in purposes, sized for
// the paired algorithm (ECDSA P-256 for ES256, RSA-2048 for PS256,
// Ed25519 for EdDSA — the three algorithms this module supports).
func NewKeyManager(purposes map[keys.SigningPurpose]fapi.SignatureAlgorithm) (*KeyManager, error) {
	m := &KeyManager{
		keys: make(map[keys.SigningPurpose]crypto.Signer, len(purposes)),
		kid:  make(map[keys.SigningPurpose]string, len(purposes)),
	}
	for purpose, alg := range purposes {
		signer, err := generateSigner(alg)
		if err != nil {
			return nil, fmt.Errorf("generate key for purpose %v: %w", purpose, err)
		}
		m.keys[purpose] = signer
		m.kid[purpose] = fmt.Sprintf("ephemeral-%d-%s", purpose, alg.String())
	}
	return m, nil
}

func generateSigner(alg fapi.SignatureAlgorithm) (crypto.Signer, error) {
	switch alg {
	case fapi.ES256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case fapi.PS256:
		return rsa.GenerateKey(rand.Reader, 2048)
	case fapi.EdDSA:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	default:
		return nil, fmt.Errorf("unsupported algorithm %v", alg)
	}
}

// Sign implements keys.KeyManager.
func (m *KeyManager) Sign(_ context.Context, req keys.SigningRequest) (keys.Signature, error) {
	m.mu.Lock()
	signer, ok := m.keys[req.Purpose]
	kid := m.kid[req.Purpose]
	m.mu.Unlock()
	if !ok {
		return keys.Signature{}, fmt.Errorf("ephemeral: no key for purpose %v", req.Purpose)
	}

	switch key := signer.(type) {
	case *ecdsa.PrivateKey:
		sig, err := ecdsa.SignASN1(rand.Reader, key, req.Digest)
		if err != nil {
			return keys.Signature{}, err
		}
		return keys.Signature{KeyID: kid, Value: sig}, nil
	case *rsa.PrivateKey:
		sig, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, req.Digest, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256,
		})
		if err != nil {
			return keys.Signature{}, err
		}
		return keys.Signature{KeyID: kid, Value: sig}, nil
	case ed25519.PrivateKey:
		// req.SigningInput, not req.Digest: EdDSA signs the raw message
		// (RFC 8037 §3.1), never a pre-hashed digest — see
		// keys.SigningRequest's own doc comment.
		sig := ed25519.Sign(key, req.SigningInput)
		return keys.Signature{KeyID: kid, Value: sig}, nil
	default:
		return keys.Signature{}, fmt.Errorf("ephemeral: unsupported key type %T", signer)
	}
}

// PublicKey implements keys.KeyManager.
func (m *KeyManager) PublicKey(_ context.Context, purpose keys.SigningPurpose, _ fapi.SignatureAlgorithm) (keys.PublicKeyInfo, error) {
	m.mu.Lock()
	signer, ok := m.keys[purpose]
	kid := m.kid[purpose]
	m.mu.Unlock()
	if !ok {
		return keys.PublicKeyInfo{}, fmt.Errorf("ephemeral: no key for purpose %v", purpose)
	}
	return keys.PublicKeyInfo{KeyID: kid, PublicKey: signer.Public()}, nil
}

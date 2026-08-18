package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"sync"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
)

// ephemeralKeyManager is a keys.KeyManager backed by fresh in-memory
// ES256 keys generated once at process startup, one per active signing
// purpose — the same shape as cmd/conformance-as's key manager, mirrored
// here because both roles share the keys.KeyManager contract (see
// ARCHITECTURE.md design rule 5). This driver registers its generated
// public keys with the suite in the very same run (see plan.go), so
// there is never a reason to persist a private key across runs.
type ephemeralKeyManager struct {
	mu   sync.Mutex
	keys map[keys.SigningPurpose]*ecdsa.PrivateKey
	kid  map[keys.SigningPurpose]string
}

// newEphemeralKeyManager generates one ES256 key per purpose in purposes.
func newEphemeralKeyManager(purposes []keys.SigningPurpose) (*ephemeralKeyManager, error) {
	m := &ephemeralKeyManager{
		keys: make(map[keys.SigningPurpose]*ecdsa.PrivateKey, len(purposes)),
		kid:  make(map[keys.SigningPurpose]string, len(purposes)),
	}
	for _, purpose := range purposes {
		signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate key for purpose %v: %w", purpose, err)
		}
		m.keys[purpose] = signer
		m.kid[purpose] = fmt.Sprintf("conformance-client-%d", purpose)
	}
	return m, nil
}

// Sign implements keys.KeyManager.
func (m *ephemeralKeyManager) Sign(_ context.Context, req keys.SigningRequest) (keys.Signature, error) {
	m.mu.Lock()
	signer, ok := m.keys[req.Purpose]
	kid := m.kid[req.Purpose]
	m.mu.Unlock()
	if !ok {
		return keys.Signature{}, fmt.Errorf("conformance-client: no key for purpose %v", req.Purpose)
	}
	sig, err := ecdsa.SignASN1(rand.Reader, signer, req.Digest)
	if err != nil {
		return keys.Signature{}, err
	}
	return keys.Signature{KeyID: kid, Value: sig}, nil
}

// PublicKey implements keys.KeyManager.
func (m *ephemeralKeyManager) PublicKey(_ context.Context, purpose keys.SigningPurpose, _ fapi.SignatureAlgorithm) (keys.PublicKeyInfo, error) {
	m.mu.Lock()
	signer, ok := m.keys[purpose]
	kid := m.kid[purpose]
	m.mu.Unlock()
	if !ok {
		return keys.PublicKeyInfo{}, fmt.Errorf("conformance-client: no key for purpose %v", purpose)
	}
	return keys.PublicKeyInfo{KeyID: kid, PublicKey: crypto.PublicKey(signer.Public())}, nil
}

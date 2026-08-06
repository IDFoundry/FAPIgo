package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"sync"

	fapi "github.com/osanderson/go-fapi"
	"github.com/osanderson/go-fapi/keys"
)

// ephemeralKeyManager is a keys.KeyManager backed by fresh in-memory keys
// generated once at process startup, one per active signing purpose.
//
// The OIDF conformance suite fetches jwks_uri live on every test run and
// never needs to verify a signature across a process restart, so
// persisting these private keys to disk would be an operational
// liability (a stray private key file) with no conformance benefit.
// Revisit only if a specific test module needs key rollover.
type ephemeralKeyManager struct {
	mu   sync.Mutex
	keys map[keys.SigningPurpose]crypto.Signer
	kid  map[keys.SigningPurpose]string
}

// newEphemeralKeyManager generates one key per purpose in purposes, sized
// for the paired algorithm (ECDSA P-256 for ES256, RSA-2048 for PS256 —
// the only two algorithms this module supports).
func newEphemeralKeyManager(purposes map[keys.SigningPurpose]fapi.SignatureAlgorithm) (*ephemeralKeyManager, error) {
	m := &ephemeralKeyManager{
		keys: make(map[keys.SigningPurpose]crypto.Signer, len(purposes)),
		kid:  make(map[keys.SigningPurpose]string, len(purposes)),
	}
	for purpose, alg := range purposes {
		signer, err := generateSigner(alg)
		if err != nil {
			return nil, fmt.Errorf("generate key for purpose %v: %w", purpose, err)
		}
		m.keys[purpose] = signer
		m.kid[purpose] = fmt.Sprintf("as-%d-%s", purpose, alg.String())
	}
	return m, nil
}

func generateSigner(alg fapi.SignatureAlgorithm) (crypto.Signer, error) {
	switch alg {
	case fapi.ES256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case fapi.PS256:
		return rsa.GenerateKey(rand.Reader, 2048)
	default:
		return nil, fmt.Errorf("unsupported algorithm %v", alg)
	}
}

// Sign implements keys.KeyManager.
func (m *ephemeralKeyManager) Sign(_ context.Context, req keys.SigningRequest) (keys.Signature, error) {
	m.mu.Lock()
	signer, ok := m.keys[req.Purpose]
	kid := m.kid[req.Purpose]
	m.mu.Unlock()
	if !ok {
		return keys.Signature{}, fmt.Errorf("conformance-as: no key for purpose %v", req.Purpose)
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
	default:
		return keys.Signature{}, fmt.Errorf("conformance-as: unsupported key type %T", signer)
	}
}

// PublicKey implements keys.KeyManager.
func (m *ephemeralKeyManager) PublicKey(_ context.Context, purpose keys.SigningPurpose, _ fapi.SignatureAlgorithm) (keys.PublicKeyInfo, error) {
	m.mu.Lock()
	signer, ok := m.keys[purpose]
	kid := m.kid[purpose]
	m.mu.Unlock()
	if !ok {
		return keys.PublicKeyInfo{}, fmt.Errorf("conformance-as: no key for purpose %v", purpose)
	}
	return keys.PublicKeyInfo{KeyID: kid, PublicKey: signer.Public()}, nil
}

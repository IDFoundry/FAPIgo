package fapitest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"sync"
	"testing"

	fapi "github.com/osanderson/go-fapi"
	"github.com/osanderson/go-fapi/keys"
)

// memKeyManager is an in-memory keys.KeyManager backed by real ECDSA
// keys, one per SigningPurpose — used for both the simulated
// authorization server's own signing keys and the simulated client's.
// Signatures it produces are genuine ASN.1 DER ECDSA signatures, so
// internal/jose's Sign/Verify pair works against it exactly as it would
// against a real crypto.Signer.
type memKeyManager struct {
	mu   sync.Mutex
	keys map[keys.SigningPurpose]*ecdsa.PrivateKey
	kid  map[keys.SigningPurpose]string
}

// newMemKeyManager generates one P-256 key per purpose in purposes.
func newMemKeyManager(t *testing.T, prefix string, purposes ...keys.SigningPurpose) *memKeyManager {
	t.Helper()
	m := &memKeyManager{
		keys: make(map[keys.SigningPurpose]*ecdsa.PrivateKey, len(purposes)),
		kid:  make(map[keys.SigningPurpose]string, len(purposes)),
	}
	for _, p := range purposes {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("fapitest: generate key for purpose %v: %v", p, err)
		}
		m.keys[p] = priv
		m.kid[p] = fmt.Sprintf("%s-%d", prefix, p)
	}
	return m
}

func (m *memKeyManager) Sign(ctx context.Context, req keys.SigningRequest) (keys.Signature, error) {
	m.mu.Lock()
	priv, ok := m.keys[req.Purpose]
	m.mu.Unlock()
	if !ok {
		return keys.Signature{}, fmt.Errorf("fapitest: no key for purpose %v", req.Purpose)
	}
	sig, err := ecdsa.SignASN1(rand.Reader, priv, req.Digest)
	if err != nil {
		return keys.Signature{}, err
	}
	return keys.Signature{KeyID: m.kid[req.Purpose], Value: sig}, nil
}

func (m *memKeyManager) PublicKey(ctx context.Context, purpose keys.SigningPurpose, algorithm fapi.SignatureAlgorithm) (keys.PublicKeyInfo, error) {
	m.mu.Lock()
	priv, ok := m.keys[purpose]
	kid := m.kid[purpose]
	m.mu.Unlock()
	if !ok {
		return keys.PublicKeyInfo{}, fmt.Errorf("fapitest: no key for purpose %v", purpose)
	}
	return keys.PublicKeyInfo{KeyID: kid, PublicKey: &priv.PublicKey}, nil
}

// memClientKeySource adapts a client's memKeyManager to keys.ClientKeySource
// — the server-side contract for resolving a registered client's
// verification keys — by mapping each VerificationPurpose to the
// matching SigningPurpose the client actually signed with.
type memClientKeySource struct {
	clientID fapi.ClientID
	manager  *memKeyManager
}

func (s *memClientKeySource) ResolveVerificationKeys(ctx context.Context, req keys.ClientKeyRequest) (keys.VerificationKeySet, error) {
	if req.ClientID != s.clientID {
		return keys.VerificationKeySet{}, fmt.Errorf("fapitest: unknown client %q", req.ClientID)
	}
	purpose, err := signingPurposeFor(req.Purpose)
	if err != nil {
		return keys.VerificationKeySet{}, err
	}
	info, err := s.manager.PublicKey(ctx, purpose, req.Algorithm)
	if err != nil {
		return keys.VerificationKeySet{}, err
	}
	return keys.VerificationKeySet{Keys: []keys.VerificationKey{
		{KeyID: info.KeyID, Algorithm: req.Algorithm, PublicKey: info.PublicKey},
	}}, nil
}

func signingPurposeFor(p keys.VerificationPurpose) (keys.SigningPurpose, error) {
	switch p {
	case keys.ClientAssertionVerification:
		return keys.ClientAuthentication, nil
	case keys.RequestObjectVerification:
		return keys.RequestObjectSigning, nil
	default:
		return 0, fmt.Errorf("fapitest: unsupported verification purpose %v", p)
	}
}

// memIssuerKeySource adapts an authorization server's memKeyManager to
// keys.IssuerKeySource — used by client to verify a JARM response or ID
// token, and by resource to verify an access token.
type memIssuerKeySource struct {
	issuer  string
	manager *memKeyManager
}

func (s *memIssuerKeySource) ResolveIssuerKeys(ctx context.Context, req keys.IssuerKeyRequest) (keys.IssuerKeySet, error) {
	if req.Issuer != s.issuer {
		return keys.IssuerKeySet{}, fmt.Errorf("fapitest: unknown issuer %q", req.Issuer)
	}
	purpose, err := issuerSigningPurposeFor(req.Purpose)
	if err != nil {
		return keys.IssuerKeySet{}, err
	}
	info, err := s.manager.PublicKey(ctx, purpose, req.Algorithm)
	if err != nil {
		return keys.IssuerKeySet{}, err
	}
	return keys.IssuerKeySet{Keys: []keys.IssuerKey{
		{KeyID: info.KeyID, Algorithm: req.Algorithm, PublicKey: info.PublicKey},
	}}, nil
}

func issuerSigningPurposeFor(p keys.IssuerVerificationPurpose) (keys.SigningPurpose, error) {
	switch p {
	case keys.AccessTokenVerification:
		return keys.AccessTokenSigning, nil
	case keys.JARMVerification:
		return keys.JARMSigning, nil
	case keys.IDTokenVerification:
		return keys.IDTokenSigning, nil
	default:
		return 0, fmt.Errorf("fapitest: unsupported issuer verification purpose %v", p)
	}
}

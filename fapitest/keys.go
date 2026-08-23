package fapitest

import (
	"context"
	"fmt"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/keys/ephemeral"
)

// newAlgorithmKeyManager generates one key per purpose in purposes,
// each sized for algorithm — a thin t.Fatalf-on-error wrapper around
// ephemeral.NewKeyManager, used for both the simulated authorization
// server's own signing keys and the simulated client's. Reusing
// keys/ephemeral here (rather than fapitest keeping its own duplicate
// key-generation code) is what makes every SignatureAlgorithm this
// module supports, EdDSA included, available to a fapitest-based test
// without fapitest tracking algorithm support of its own.
func newAlgorithmKeyManager(t *testing.T, algorithm fapi.SignatureAlgorithm, purposes ...keys.SigningPurpose) *ephemeral.KeyManager {
	t.Helper()
	m := make(map[keys.SigningPurpose]fapi.SignatureAlgorithm, len(purposes))
	for _, p := range purposes {
		m[p] = algorithm
	}
	manager, err := ephemeral.NewKeyManager(m)
	if err != nil {
		t.Fatalf("fapitest: build key manager: %v", err)
	}
	return manager
}

// memClientKeySource adapts a client's keys.KeyManager (an
// *ephemeral.KeyManager in practice — see newAlgorithmKeyManager) to
// keys.ClientKeySource — the server-side contract for resolving a
// registered client's verification keys — by mapping each
// VerificationPurpose to the matching SigningPurpose the client
// actually signed with.
type memClientKeySource struct {
	clientID fapi.ClientID
	manager  keys.KeyManager
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

// memIssuerKeySource adapts an authorization server's keys.KeyManager to
// keys.IssuerKeySource — used by client to verify a JARM response or ID
// token, and by resource to verify an access token.
type memIssuerKeySource struct {
	issuer  string
	manager keys.KeyManager
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

// memClientEncryptionKeySource adapts a client's keys.Decrypter to
// keys.ClientEncryptionKeySource — the server-side contract for
// resolving a registered client's encryption key when issuing it an
// encrypted ID token — by delegating to EncryptionPublicKey, the
// client-side method that hands back the public half of the same key
// UnwrapContentEncryptionKey will later use to decrypt. Only used when
// Config.EncryptIDTokens is set.
type memClientEncryptionKeySource struct {
	clientID  fapi.ClientID
	decrypter keys.Decrypter
}

func (s *memClientEncryptionKeySource) ResolveEncryptionKeys(ctx context.Context, req keys.ClientEncryptionKeyRequest) (keys.ClientEncryptionKeySet, error) {
	if req.ClientID != s.clientID {
		return keys.ClientEncryptionKeySet{}, fmt.Errorf("fapitest: unknown client %q", req.ClientID)
	}
	info, err := s.decrypter.EncryptionPublicKey(ctx, keys.IDTokenDecryption, req.Algorithm)
	if err != nil {
		return keys.ClientEncryptionKeySet{}, err
	}
	return keys.ClientEncryptionKeySet{Keys: []keys.ClientEncryptionKey{
		{KeyID: info.KeyID, Algorithm: req.Algorithm, PublicKey: info.PublicKey},
	}}, nil
}

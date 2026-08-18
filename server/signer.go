package server

import (
	"context"
	"crypto"
	"fmt"
	"io"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
)

// keyManagerSigner adapts a keys.KeyManager to crypto.Signer, so this
// server's own signing key can be used with internal/jose without ever
// exposing a crypto.Signer (or private key) through the public keys
// package. It exists only inside this package and is never handed to a
// caller.
type keyManagerSigner struct {
	ctx       context.Context
	manager   keys.KeyManager
	purpose   keys.SigningPurpose
	algorithm fapi.SignatureAlgorithm
	publicKey crypto.PublicKey
}

func (s keyManagerSigner) Public() crypto.PublicKey { return s.publicKey }

func (s keyManagerSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	sig, err := s.manager.Sign(s.ctx, keys.SigningRequest{
		Purpose: s.purpose, Algorithm: s.algorithm, Digest: digest,
	})
	if err != nil {
		return nil, err
	}
	return sig.Value, nil
}

// newSigner resolves the current public key for purpose/algorithm and
// returns a crypto.Signer-shaped adapter over Dependencies.Keys, plus
// its kid, for use with internal/jose-based signing (JARM, access
// tokens, ID tokens).
func (s *Server) newSigner(ctx context.Context, purpose keys.SigningPurpose, algorithm fapi.SignatureAlgorithm) (crypto.Signer, string, error) {
	info, err := s.deps.Keys.PublicKey(ctx, purpose, algorithm)
	if err != nil {
		return nil, "", fmt.Errorf("resolve signing key: %w", err)
	}
	signer := keyManagerSigner{
		ctx: ctx, manager: s.deps.Keys, purpose: purpose,
		algorithm: algorithm, publicKey: info.PublicKey,
	}
	return signer, info.KeyID, nil
}

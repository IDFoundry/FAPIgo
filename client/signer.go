package client

import (
	"context"
	"crypto"
	"fmt"
	"io"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
)

// keyManagerSigner adapts a keys.KeyManager to crypto.Signer, so this
// client's own signing key can be used with internal/jose without ever
// exposing a crypto.Signer (or private key) through the public keys
// package. It exists only inside this package and is never handed to a
// caller — the same pattern server uses for its own signing keys.
type keyManagerSigner struct {
	ctx       context.Context
	manager   keys.KeyManager
	purpose   keys.SigningPurpose
	algorithm fapi.SignatureAlgorithm
	publicKey crypto.PublicKey
}

func (s keyManagerSigner) Public() crypto.PublicKey { return s.publicKey }

func (s keyManagerSigner) Sign(_ io.Reader, digestOrMessage []byte, _ crypto.SignerOpts) ([]byte, error) {
	req := keys.SigningRequest{Purpose: s.purpose, Algorithm: s.algorithm}
	// EdDSA's crypto.Signer contract passes the raw signing input here,
	// never a digest (internal/jose's signEdDSA calls Sign with
	// crypto.Hash(0) precisely to request that) — see
	// keys.SigningRequest's own doc comment for why that has to land in
	// a different field than every other algorithm's Digest.
	if s.algorithm == fapi.EdDSA {
		req.SigningInput = digestOrMessage
	} else {
		req.Digest = digestOrMessage
	}
	sig, err := s.manager.Sign(s.ctx, req)
	if err != nil {
		return nil, err
	}
	return sig.Value, nil
}

// newSigner resolves the current public key for purpose/algorithm and
// returns a crypto.Signer-shaped adapter over Dependencies.Keys, plus
// its kid, for use with internal/jose-based signing (client assertions,
// request objects, DPoP proofs).
func (c *Client) newSigner(ctx context.Context, purpose keys.SigningPurpose, algorithm fapi.SignatureAlgorithm) (crypto.Signer, string, error) {
	info, err := c.deps.Keys.PublicKey(ctx, purpose, algorithm)
	if err != nil {
		return nil, "", fmt.Errorf("resolve signing key: %w", err)
	}
	signer := keyManagerSigner{
		ctx: ctx, manager: c.deps.Keys, purpose: purpose,
		algorithm: algorithm, publicKey: info.PublicKey,
	}
	return signer, info.KeyID, nil
}

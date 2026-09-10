package client

import (
	"context"
	"crypto"
	"fmt"
	"io"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/storage"
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
	sig, err := s.manager.Sign(s.ctx, keys.NewSigningRequest(s.purpose, s.algorithm, digestOrMessage))
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

// addClientAuthentication adds this client's authentication to form — a
// freshly signed client_assertion (new iat and jti every call, exactly
// as single-use as a DPoP proof — see ExchangeCode's own buildTokenForm
// doc comment for why reusing one across a retry gets rejected as jti
// replay) under ClientAuthMethodPrivateKeyJWT, or a plain client_id
// under any RFC 8705 §2 mTLS method, where the TLS certificate
// Dependencies.HTTP's own transport presents is the credential instead.
// Shared by every closure that builds a token-endpoint form —
// ExchangeCode, PollBackchannelAuthentication, and
// RequestClientCredentialsToken — so this decision lives in one place
// rather than being reimplemented per call site.
func (c *Client) addClientAuthentication(form map[string]string, assertionSigner crypto.Signer, assertionKID string) error {
	if c.cfg.ClientAuthMethod != storage.ClientAuthMethodPrivateKeyJWT {
		form["client_id"] = c.cfg.ClientID.String()
		return nil
	}
	assertion, err := clientassertion.CreateAssertion(clientassertion.AssertionRequest{
		Signer: assertionSigner, Algorithm: c.cfg.Algorithms.ClientAuthentication, KeyID: assertionKID,
		ClientID: c.cfg.ClientID.String(), Audience: c.cfg.Issuer.String(),
		Now: c.deps.Clock.Now(), Lifetime: c.cfg.Limits.ClientAssertionLifetime, Random: c.deps.Random,
	})
	if err != nil {
		return err
	}
	form["client_assertion"] = assertion
	form["client_assertion_type"] = clientassertion.AssertionType
	return nil
}

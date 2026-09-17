package client

import (
	"context"
	"fmt"

	"github.com/idfoundry/fapigo/internal/clientattestation"
	"github.com/idfoundry/fapigo/keys"
)

// AttestationSource supplies the pre-issued Client Attestation JWT this
// client attaches under storage.ClientAuthMethodAttestation
// (draft-ietf-oauth-attestation-based-client-auth-07 §10.2) — an
// opaque, out-of-band-issued, reusable credential this package never
// constructs itself. A real implementation typically wraps a wallet
// app's own OS/hardware attestation API or its backend Attester,
// refreshing the held JWT once it nears whatever validity window the
// Attester gave it; CurrentAttestation is called fresh on every
// request rather than cached by this package, so the refresh policy
// lives entirely in the implementation.
type AttestationSource interface {
	// CurrentAttestation returns the Client Attestation JWT to present
	// on this request. Its own "sub" claim must equal Config.ClientID,
	// and its "cnf.jwk" claim must name the public half of the Client
	// Instance Key Dependencies.Keys signs Client Attestation PoP JWTs
	// with under keys.ClientAttestationPoPSigning — this package never
	// checks either correspondence itself.
	CurrentAttestation(ctx context.Context) (string, error)
}

const (
	// attestationHeader carries the held Client Attestation JWT
	// (draft-07 §5.1) — never sent as a client_id/client_assertion*
	// form field (see addClientAuthentication's own doc comment).
	attestationHeader = "OAuth-Client-Attestation"

	// attestationPoPHeader carries the freshly signed Client
	// Attestation PoP JWT (draft-07 §5.2) — see attestationHeaders'
	// own doc comment.
	attestationPoPHeader = "OAuth-Client-Attestation-PoP"
)

// attestationHeaders builds the two Attestation-Based Client
// Authentication headers for one outbound request: the held Client
// Attestation JWT, fetched fresh via Dependencies.Attestation since
// this package never caches it itself, plus a freshly signed,
// single-use Client Attestation PoP JWT signed with the Client
// Instance Key (Dependencies.Keys, keys.ClientAttestationPoPSigning).
// The PoP is exactly as single-use as a DPoP proof or a
// private_key_jwt client assertion is (see ExchangeCode's own
// buildTokenForm doc comment), so this is called again for every
// retry rather than reused.
func (c *Client) attestationHeaders(ctx context.Context) (map[string]string, error) {
	attestation, err := c.deps.Attestation.CurrentAttestation(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve client attestation: %w", err)
	}
	instanceSigner, _, err := c.newSigner(ctx, keys.ClientAttestationPoPSigning, c.cfg.Algorithms.ClientAttestationPoP)
	if err != nil {
		return nil, fmt.Errorf("resolve client attestation instance key: %w", err)
	}
	pop, err := clientattestation.CreatePoP(clientattestation.PoPCreateRequest{
		Signer: instanceSigner, Algorithm: c.cfg.Algorithms.ClientAttestationPoP,
		ClientID: c.cfg.ClientID, Audience: c.cfg.Issuer.String(),
		Now: c.deps.Clock.Now(), Random: c.deps.Random,
	})
	if err != nil {
		return nil, fmt.Errorf("build client attestation PoP: %w", err)
	}
	return map[string]string{
		attestationHeader:    attestation,
		attestationPoPHeader: pop,
	}, nil
}

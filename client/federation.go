package client

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/idfoundry/fapigo/federation"
	"github.com/idfoundry/fapigo/keys"
)

// EntityConfiguration signs and returns this client's own OpenID
// Federation 1.0 Entity Configuration (federation.SelfIssuer's own
// EntityConfiguration), carrying metadata as its own "metadata" claim —
// build it yourself, typically a federation_entity object plus an
// openid_relying_party object mirroring this client's own registered
// capabilities, and pass it here; this method only resolves this
// client's own federation signing key and signs — it never derives
// metadata from Config on its own. Serve the result verbatim, with
// Content-Type federation.EntityStatementContentType, at
// Config.Federation.EntityID+federation.WellKnownPath — this package
// still doesn't own HTTP transport itself.
//
// Fails if Config.Federation.EntityID is unset — see FederationConfig's
// own doc comment.
func (c *Client) EntityConfiguration(ctx context.Context, metadata map[string]json.RawMessage) (string, error) {
	if c.cfg.Federation.EntityID == "" {
		return "", fmt.Errorf("client: federation self-issuance is not configured (config.federation.entity_id is empty)")
	}
	signer, kid, err := c.newSigner(ctx, keys.FederationEntitySigning, c.cfg.Federation.Algorithm)
	if err != nil {
		return "", fmt.Errorf("client: resolve federation signing key: %w", err)
	}
	keySet, err := keys.PublicJWKS(ctx, []keys.SigningKeyUse{
		{Manager: c.deps.Keys, Purpose: keys.FederationEntitySigning, Algorithm: c.cfg.Federation.Algorithm},
	}, nil)
	if err != nil {
		return "", fmt.Errorf("client: build federation jwks: %w", err)
	}
	jwks, err := json.Marshal(keySet)
	if err != nil {
		return "", fmt.Errorf("client: marshal federation jwks: %w", err)
	}

	issuer, err := federation.NewSelfIssuer(federation.SelfIssueConfig{
		EntityID:       c.cfg.Federation.EntityID,
		AuthorityHints: c.cfg.Federation.AuthorityHints,
		Lifetime:       c.cfg.Federation.Lifetime,
	}, federation.SelfIssueDependencies{
		Signer: signer, Algorithm: c.cfg.Federation.Algorithm, KeyID: kid,
		JWKS: jwks, Clock: c.deps.Clock,
	})
	if err != nil {
		return "", fmt.Errorf("client: %w", err)
	}
	return issuer.EntityConfiguration(metadata)
}

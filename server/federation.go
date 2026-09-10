package server

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/idfoundry/fapigo/federation"
	"github.com/idfoundry/fapigo/keys"
)

// EntityConfiguration signs and returns this server's own OpenID
// Federation 1.0 Entity Configuration (federation.SelfIssuer's own
// EntityConfiguration), carrying metadata as its own "metadata" claim —
// build it yourself, typically a federation_entity object plus an
// openid_provider object mirroring this server's own Metadata, and pass
// it here; this method only resolves this server's own federation
// signing key and signs — it never derives metadata from Config on its
// own. Serve the result verbatim, with Content-Type
// federation.EntityStatementContentType, at
// Config.Federation.EntityID+federation.WellKnownPath — this package
// still doesn't own HTTP transport itself.
//
// Fails if Config.Federation.EntityID is unset — see FederationConfig's
// own doc comment.
func (s *Server) EntityConfiguration(ctx context.Context, metadata map[string]json.RawMessage) (string, error) {
	if s.cfg.Federation.EntityID == "" {
		return "", fmt.Errorf("server: federation self-issuance is not configured (config.federation.entity_id is empty)")
	}
	signer, kid, err := s.newSigner(ctx, keys.FederationEntitySigning, s.cfg.Federation.Algorithm)
	if err != nil {
		return "", fmt.Errorf("server: resolve federation signing key: %w", err)
	}
	keySet, err := keys.PublicJWKS(ctx, []keys.SigningKeyUse{
		{Manager: s.deps.Keys, Purpose: keys.FederationEntitySigning, Algorithm: s.cfg.Federation.Algorithm},
	}, nil)
	if err != nil {
		return "", fmt.Errorf("server: build federation jwks: %w", err)
	}
	jwks, err := json.Marshal(keySet)
	if err != nil {
		return "", fmt.Errorf("server: marshal federation jwks: %w", err)
	}

	issuer, err := federation.NewSelfIssuer(federation.SelfIssueConfig{
		EntityID:       s.cfg.Federation.EntityID,
		AuthorityHints: s.cfg.Federation.AuthorityHints,
		Lifetime:       s.cfg.Federation.Lifetime,
	}, federation.SelfIssueDependencies{
		Signer: signer, Algorithm: s.cfg.Federation.Algorithm, KeyID: kid,
		JWKS: jwks, Clock: s.deps.Clock,
	})
	if err != nil {
		return "", fmt.Errorf("server: %w", err)
	}
	return issuer.EntityConfiguration(metadata)
}

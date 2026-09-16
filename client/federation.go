package client

import (
	"context"
	"encoding/json"
	"fmt"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/federation"
	"github.com/idfoundry/fapigo/internal/metadata"
	"github.com/idfoundry/fapigo/keys"
)

// openIDProviderEntityType is the Entity Type Identifier an
// authorization server's own OpenID Provider metadata is published
// under (OpenID Federation 1.0 §5.1, mirroring federation's own
// unexported relyingPartyEntityType, which server/federation.go's own
// side of this reads for the opposite role).
const openIDProviderEntityType = "openid_provider"

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

// DiscoverViaFederation resolves issuer's OpenID Federation 1.0 Trust
// Chain via resolver and returns the endpoints and algorithm support a
// caller needs to build a Config — the federation counterpart of
// Discover, returning the identical DiscoveredMetadata shape so a
// caller's downstream code (SupportsAlgorithms, IssuerKeySource,
// building Config) never needs to know which discovery mechanism
// produced it. issuer is a federation Entity Identifier (a plain
// string, per federation's own convention — see federation.ValidEntityID),
// not a fapi.URL.
//
// This is a meaningfully stronger trust basis than Discover's own bare
// TLS fetch: resolved.Metadata's own "openid_provider" object has
// already been cryptographically verified end to end by resolver
// (signature-checked at every hop, policy-merged, constraint-checked)
// before this function ever reads it, rather than being a single live
// fetch that could be redirected, cached, or substituted the way OIDC
// Discovery 1.0 §4.3's own anti-spoofing "issuer must match" check
// exists to guard against — that identical check is still performed
// here too, against resolved.EntityID, since "openid_provider" metadata
// carries its own "issuer" claim by OIDC Discovery 1.0 convention
// regardless of how it was obtained.
//
// The operational keys DiscoveredMetadata.JWKSURI/.IssuerKeySource
// point at are still fetched live over HTTP, exactly as Discover's own
// are: resolved.JWKS is a different key entirely (this issuer's own
// federation signing key, used to sign Entity/Subordinate Statements —
// see federation/doc.go), never the operational key it signs ID tokens
// or JARM responses with.
func DiscoverViaFederation(ctx context.Context, resolver *federation.Resolver, issuer string, opts ...fapi.URLOption) (DiscoveredMetadata, error) {
	if resolver == nil {
		return DiscoveredMetadata{}, fmt.Errorf("client: discover via federation: resolver is required")
	}
	if issuer == "" {
		return DiscoveredMetadata{}, fmt.Errorf("client: discover via federation: issuer is required")
	}

	resolved, err := resolver.Resolve(ctx, issuer)
	if err != nil {
		return DiscoveredMetadata{}, fmt.Errorf("client: discover via federation: resolve trust chain: %w", err)
	}
	raw, ok := resolved.Metadata[openIDProviderEntityType]
	if !ok {
		return DiscoveredMetadata{}, fmt.Errorf("client: discover via federation: %q has no %s metadata", issuer, openIDProviderEntityType)
	}
	doc, err := metadata.ParseAndValidate(raw, resolved.EntityID)
	if err != nil {
		return DiscoveredMetadata{}, fmt.Errorf("client: discover via federation: %w", err)
	}
	return buildDiscoveredMetadata(doc, opts...)
}

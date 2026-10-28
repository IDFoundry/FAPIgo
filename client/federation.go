package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/federation"
	"github.com/idfoundry/fapigo/internal/metadata"
	"github.com/idfoundry/fapigo/internal/strictjson"
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
// regardless of how it was obtained. The OP must also advertise
// Automatic Registration ("automatic" in
// client_registration_types_supported, OpenID Federation 1.0 §12.1) —
// the only registration type this package supports.
//
// The operational keys DiscoveredMetadata.JWKSURI/.IssuerKeySource
// point at are still fetched live over HTTP, exactly as Discover's own
// are: resolved.JWKS is a different key entirely (this issuer's own
// federation signing key, used to sign Entity/Subordinate Statements —
// see federation/doc.go), never the operational key it signs ID tokens
// or JARM responses with.
//
// In production, resolver's Dependencies.HTTP must be fapihttp.New over
// fapihttp.NewClient's client (HardenedForProduction): neither this nor
// federation.NewResolver takes an assurance level, so neither can check.
// This matters most when issuer comes from the user (a relying party
// letting them choose their OP): Resolve then fetches that entity's
// Entity Configuration and every superior its authority_hints name, all
// chosen by whoever controls that entity, and only NewClient's
// transport stops a DNS answer that changes after validation (DNS
// rebinding) from aiming those fetches at an internal host.
//
// The Trust Chain expires (ResolvedEntity().ExpiresAt, the earliest
// expiry of its statements), and OpenID Federation 1.0 §12.3 forbids
// using the OP past it. A Client NewFromDiscovery builds from this
// metadata enforces that with ErrTrustChainExpired; call
// DiscoverViaFederation again, and build a new Client, before then.
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
	if err := requireAutomaticRegistration(raw); err != nil {
		return DiscoveredMetadata{}, fmt.Errorf("client: discover via federation: %w", err)
	}
	md, err := buildDiscoveredMetadata(doc, opts...)
	if err != nil {
		return DiscoveredMetadata{}, err
	}
	md.resolved = &resolved
	return md, nil
}

// requireAutomaticRegistration checks that an OP's "openid_provider"
// metadata advertises Automatic Registration — the only registration
// type this package's federation support uses (see EntityConfiguration).
// OpenID Federation 1.0 §12.1: "An OP that supports Automatic
// Registration MUST include the automatic keyword in its
// client_registration_types_supported metadata parameter." Values this
// package doesn't recognize alongside "automatic" are ignored.
func requireAutomaticRegistration(raw json.RawMessage) error {
	var md struct {
		ClientRegistrationTypesSupported []string `json:"client_registration_types_supported"`
	}
	if err := strictjson.Unmarshal(raw, &md); err != nil {
		return fmt.Errorf("parse client_registration_types_supported: %w", err)
	}
	if !slices.Contains(md.ClientRegistrationTypesSupported, "automatic") {
		return fmt.Errorf("openid_provider metadata client_registration_types_supported %q does not include \"automatic\"", md.ClientRegistrationTypesSupported)
	}
	return nil
}

// ErrTrustChainExpired is returned by BeginAuthorization,
// BeginBackchannelAuthentication, RequestClientCredentialsToken and
// RefreshTokens on a Client NewFromDiscovery built from
// DiscoverViaFederation's metadata, once the authorization server's
// Trust Chain has expired. OpenID Federation 1.0 §12.3 says an RP "MUST
// NOT use it past the expiration of the Trust Chain" and that "the
// trust in the OP MUST be successfully reevaluated before continuing";
// §11 has every participant "support refreshing a Trust Chain when it
// expires". Resolve the chain again with DiscoverViaFederation and
// build a new Client from the result, before TrustChainExpiresAt to
// avoid the error. A flow already begun (CompleteAuthorization,
// ExchangeCode, PollBackchannelToken) isn't interrupted.
var ErrTrustChainExpired = errors.New("client: the authorization server's Trust Chain has expired: resolve it again with DiscoverViaFederation and build a new Client")

// TrustChainExpiresAt is when the authorization server's Trust Chain
// expires, for a Client NewFromDiscovery built from
// DiscoverViaFederation's metadata (ok is false otherwise): from then
// on, the methods ErrTrustChainExpired lists refuse to run.
func (c *Client) TrustChainExpiresAt() (expiresAt time.Time, ok bool) {
	return c.trustChainExpiresAt, !c.trustChainExpiresAt.IsZero()
}

// checkTrustChain returns ErrTrustChainExpired once the Trust Chain this
// Client was built from has expired.
func (c *Client) checkTrustChain() error {
	if c.trustChainExpiresAt.IsZero() || c.deps.Clock.Now().Before(c.trustChainExpiresAt) {
		return nil
	}
	return fmt.Errorf("%w (it expired at %s)", ErrTrustChainExpired, c.trustChainExpiresAt.UTC().Format(time.RFC3339))
}

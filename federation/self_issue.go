package federation

import (
	"crypto"
	"encoding/json"
	"fmt"
	"time"

	fapi "github.com/idfoundry/fapigo"
	intfed "github.com/idfoundry/fapigo/internal/federation"
)

// SelfIssueConfig configures a SelfIssuer's own Entity Identifier and
// Trust Chain routing. It is copied by NewSelfIssuer; mutating a
// SelfIssueConfig after passing it to NewSelfIssuer has no effect.
type SelfIssueConfig struct {
	// EntityID is this entity's own Entity Identifier (OpenID
	// Federation 1.0 §1.2) — an https URL, conventionally the same
	// origin EntityConfiguration's output is served from (at
	// WellKnownPath). Required.
	EntityID string

	// AuthorityHints is the "authority_hints" claim (OpenID Federation
	// 1.0 §3.1): the Entity Identifier(s) of this entity's Immediate
	// Superior(s) in a federation, whose Subordinate Statement about
	// this entity a Resolver fetches next while walking a Trust Chain
	// rooted at this entity. Nil for an entity with no federation
	// superior of its own (a Trust Anchor, or one establishing trust
	// some other way) — EntityConfiguration then produces a statement
	// with no path onward, exactly as Resolver.Resolve's own "no
	// authority_hints and not a configured trust anchor" error expects
	// unless this entity is itself a pre-configured TrustAnchor for
	// whichever Resolver is asked to resolve it.
	AuthorityHints []string

	// Lifetime bounds how far in the future EntityConfiguration's own
	// "exp" claim is set, relative to Dependencies.Clock. Required —
	// there is no implicit default.
	Lifetime time.Duration
}

// SelfIssueDependencies are a SelfIssuer's injected collaborators.
// NewSelfIssuer rejects a nil/zero value for every field — there is no
// implicit default signer, key, or clock.
type SelfIssueDependencies struct {
	// Signer produces this entity's own Entity Configuration signature
	// — its federation signing key, distinct from (and never reused as)
	// whatever key a client or server package's own Config already
	// signs OAuth/OIDC artifacts with, matching this module's existing
	// key-separation precedent for every other signing use
	// (ARCHITECTURE.md).
	Signer crypto.Signer

	// Algorithm Signer signs with.
	Algorithm fapi.SignatureAlgorithm

	// KeyID identifies Signer's key within JWKS — recorded in every
	// Entity Configuration's "kid" header so a verifier can select the
	// right key from JWKS without trial and error.
	KeyID string

	// JWKS is this entity's own published federation signing key(s), as
	// a JWK Set (RFC 7517 §5) JSON object — the "jwks" claim every
	// self-signed Entity Configuration carries (OpenID Federation 1.0
	// §3.1), and what a verifier checks EntityConfiguration's own
	// signature against (Resolver.verifySelfSigned's own rule,
	// generalized to any self-signed statement).
	JWKS json.RawMessage

	Clock Clock
}

// SelfIssuer signs this entity's own Entity Configuration — the "thin,
// role-specific glue" doc.go describes client/server as each needing
// over this package, factored here since both need the identical
// capability. Construct one with NewSelfIssuer.
type SelfIssuer struct {
	cfg  SelfIssueConfig
	deps SelfIssueDependencies
}

// NewSelfIssuer validates cfg and deps and returns a SelfIssuer.
func NewSelfIssuer(cfg SelfIssueConfig, deps SelfIssueDependencies) (*SelfIssuer, error) {
	if cfg.EntityID == "" {
		return nil, fmt.Errorf("federation: config: entity ID is required")
	}
	if err := ValidEntityID(cfg.EntityID); err != nil {
		return nil, fmt.Errorf("federation: config: %w", err)
	}
	if cfg.Lifetime <= 0 {
		return nil, fmt.Errorf("federation: config: lifetime must be positive")
	}
	if deps.Signer == nil {
		return nil, fmt.Errorf("federation: dependencies: signer is required")
	}
	if len(deps.JWKS) == 0 {
		return nil, fmt.Errorf("federation: dependencies: jwks is required")
	}
	if deps.Clock == nil {
		return nil, fmt.Errorf("federation: dependencies: clock is required")
	}
	return &SelfIssuer{cfg: cfg, deps: deps}, nil
}

// EntityConfiguration signs and returns this entity's own Entity
// Configuration (OpenID Federation 1.0 §3.1: an Entity Statement with
// iss == sub == Config.EntityID), carrying metadata as its own
// "metadata" claim — e.g. a federation_entity object plus
// openid_relying_party or openid_provider, whichever role-specific
// metadata the caller already builds for its own OAuth/OIDC discovery
// document. The returned token is an entity-statement+jwt compact
// serialization meant to be served verbatim, with Content-Type
// EntityStatementContentType, at Config.EntityID+WellKnownPath — this
// package does not itself serve HTTP, matching every other role
// package's own transport-agnostic design (ARCHITECTURE.md design rule
// 6).
func (s *SelfIssuer) EntityConfiguration(metadata map[string]json.RawMessage) (string, error) {
	token, err := intfed.Create(intfed.CreateParams{
		Signer: s.deps.Signer, Algorithm: s.deps.Algorithm, KeyID: s.deps.KeyID,
		Issuer: s.cfg.EntityID, Subject: s.cfg.EntityID,
		Now: s.deps.Clock.Now(), Lifetime: s.cfg.Lifetime,
		JWKS: s.deps.JWKS, Metadata: metadata, AuthorityHints: s.cfg.AuthorityHints,
	})
	if err != nil {
		return "", fmt.Errorf("federation: self-issue entity configuration: %w", err)
	}
	return token, nil
}

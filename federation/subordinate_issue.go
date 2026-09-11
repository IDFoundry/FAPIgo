package federation

import (
	"crypto"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	fapi "github.com/idfoundry/fapigo"
	intfed "github.com/idfoundry/fapigo/internal/federation"
)

// SubordinateIssueConfig configures a SubordinateIssuer's own Entity
// Identifier and Subordinate Statement lifetime. It is copied by
// NewSubordinateIssuer; mutating a SubordinateIssueConfig afterwards has
// no effect.
type SubordinateIssueConfig struct {
	// EntityID is this entity's own Entity Identifier — the "iss" every
	// Subordinate Statement it issues carries. An entity vouching for
	// subordinates is acting as a Trust Anchor or Intermediate (OpenID
	// Federation 1.0 §3); nothing here requires it to also be a
	// SelfIssuer, though in practice it almost always is (the same
	// entity that self-issues an Entity Configuration exposing a
	// federation_fetch_endpoint is the one that then has to answer
	// requests to it). Required.
	EntityID string

	// Lifetime bounds how far in the future each Subordinate Statement's
	// own "exp" claim is set, relative to Dependencies.Clock. Required —
	// there is no implicit default.
	Lifetime time.Duration
}

// SubordinateIssueDependencies are a SubordinateIssuer's injected
// collaborators. NewSubordinateIssuer rejects a nil/zero value for every
// field — there is no implicit default signer or clock.
type SubordinateIssueDependencies struct {
	// Signer produces every Subordinate Statement's signature — this
	// entity's own federation signing key, the same one
	// SelfIssueDependencies.Signer would use for its own Entity
	// Configuration when this entity also self-issues one.
	Signer crypto.Signer

	// Algorithm Signer signs with.
	Algorithm fapi.SignatureAlgorithm

	// KeyID identifies Signer's key within this entity's own published
	// jwks — recorded in every Subordinate Statement's "kid" header.
	KeyID string

	Clock Clock
}

// SubordinateIssuer signs Subordinate Statements (OpenID Federation 1.0
// §3.2) about this entity's own Immediate Subordinates — the
// counterpart to SelfIssuer for an entity acting as a Trust Anchor or
// Intermediate. Construct one with NewSubordinateIssuer.
//
// Like every other type in this package, SubordinateIssuer is
// transport-agnostic: it signs and returns a token; serving it over
// HTTP at a federation_fetch_endpoint (OpenID Federation 1.0 §9,
// SubjectFromFetchRequest's own doc comment) is the caller's own
// responsibility, matching how SelfIssuer's own output is served at
// WellKnownPath.
type SubordinateIssuer struct {
	cfg  SubordinateIssueConfig
	deps SubordinateIssueDependencies
}

// NewSubordinateIssuer validates cfg and deps and returns a
// SubordinateIssuer.
func NewSubordinateIssuer(cfg SubordinateIssueConfig, deps SubordinateIssueDependencies) (*SubordinateIssuer, error) {
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
	if deps.Clock == nil {
		return nil, fmt.Errorf("federation: dependencies: clock is required")
	}
	return &SubordinateIssuer{cfg: cfg, deps: deps}, nil
}

// SubordinateStatementParams describes one Subordinate Statement to
// issue — the parts that vary per subordinate, unlike
// SubordinateIssueConfig's own fixed issuer identity. Deliberately a
// plain params struct, not a lookup against some
// federation.SubordinateRepository interface this package doesn't
// define: unlike a resolved client_id at PAR (AutomaticClientRepository's
// own reason for existing), nothing here needs to happen mid-request
// inside package internals — an embedder's own HTTP handler already has
// to look the subject up somehow to answer "is this actually one of my
// subordinates" before it can even call SubordinateStatement (see
// cmd/conformance-federation-trust-anchor's own /fetch handler), so
// there is no dependency-injection point this package could usefully
// own instead.
type SubordinateStatementParams struct {
	// Subject is the immediate subordinate's own Entity Identifier —
	// the "sub" claim. Required; must not equal
	// SubordinateIssueConfig.EntityID (SubordinateStatement rejects that
	// itself — OpenID Federation 1.0 §9 recommends invalid_request when
	// a fetch request's own "sub" names the issuing entity itself).
	Subject string

	// JWKS is Subject's own published federation signing key(s), as a
	// JWK Set (RFC 7517 §5) JSON object — learned out of band (the same
	// "operator captures a subordinate's key before vouching for it"
	// step cmd/conformance-federation-trust-anchor's own doc comment
	// describes), not fetched live by this package. Required.
	JWKS json.RawMessage

	// MetadataPolicy is the "metadata_policy" claim (OpenID Federation
	// 1.0 §6.1) — constraints this issuer places on Subject's own
	// metadata (and, if Subject is itself an Intermediate, its
	// subordinates' metadata in turn). Optional.
	MetadataPolicy intfed.MetadataPolicy

	// MetadataPolicyCritical is the "metadata_policy_crit" claim.
	// Optional.
	MetadataPolicyCritical []string

	// Constraints is the "constraints" claim (OpenID Federation 1.0
	// §6.2) — max_path_length, naming_constraints and
	// allowed_entity_types restrictions this issuer places on Trust
	// Chains passing through Subject. Optional.
	Constraints *intfed.Constraints

	// SourceEndpoint is the "source_endpoint" claim — the fetch endpoint
	// this statement was served from (OpenID Federation 1.0 §3.2),
	// conventionally SubordinateIssueConfig.EntityID's own
	// federation_fetch_endpoint. Optional.
	SourceEndpoint string
}

// SubordinateStatement signs and returns a Subordinate Statement
// (OpenID Federation 1.0 §3.2: an Entity Statement with iss ==
// Config.EntityID, sub == p.Subject) for p. The returned token is an
// entity-statement+jwt compact serialization meant to be served
// verbatim, with Content-Type EntityStatementContentType, from this
// entity's own federation_fetch_endpoint in response to a request
// SubjectFromFetchRequest already validated.
func (s *SubordinateIssuer) SubordinateStatement(p SubordinateStatementParams) (string, error) {
	if p.Subject == "" {
		return "", newError(ErrorInvalidRequest, http.StatusBadRequest, `"sub" is required`, nil)
	}
	if err := ValidEntityID(p.Subject); err != nil {
		return "", newError(ErrorInvalidRequest, http.StatusBadRequest, `"sub" is not a valid Entity Identifier`, err)
	}
	if p.Subject == s.cfg.EntityID {
		return "", newError(ErrorInvalidRequest, http.StatusBadRequest, `"sub" must not equal the issuing entity's own identifier`, nil)
	}
	if len(p.JWKS) == 0 {
		return "", fmt.Errorf("federation: subordinate statement: jwks is required")
	}

	token, err := intfed.Create(intfed.CreateParams{
		Signer: s.deps.Signer, Algorithm: s.deps.Algorithm, KeyID: s.deps.KeyID,
		Issuer: s.cfg.EntityID, Subject: p.Subject,
		Now: s.deps.Clock.Now(), Lifetime: s.cfg.Lifetime,
		JWKS: p.JWKS, MetadataPolicy: p.MetadataPolicy, MetadataPolicyCritical: p.MetadataPolicyCritical,
		Constraints: p.Constraints, SourceEndpoint: p.SourceEndpoint,
	})
	if err != nil {
		return "", fmt.Errorf("federation: issue subordinate statement for %q: %w", p.Subject, err)
	}
	return token, nil
}

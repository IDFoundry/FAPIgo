package federation

import (
	"crypto"
	"fmt"
	"time"

	fapi "github.com/idfoundry/fapigo"
	intfed "github.com/idfoundry/fapigo/internal/federation"
)

// TrustMarkIssueConfig configures a TrustMarkIssuer's own Entity
// Identifier. It is copied by NewTrustMarkIssuer; mutating a
// TrustMarkIssueConfig afterwards has no effect.
type TrustMarkIssueConfig struct {
	// EntityID is this entity's own Entity Identifier — the "iss" every
	// Trust Mark or Trust Mark Delegation it signs carries. Depending on
	// which method is called, this entity is acting either as a Trust
	// Mark Issuer (TrustMark) or as a Trust Mark type's real owner
	// delegating to someone else (Delegation) — OpenID Federation 1.0
	// §7 doesn't require these to be the same entity across an entire
	// federation, but a single TrustMarkIssuer always signs as one
	// fixed identity, matching SelfIssuer/SubordinateIssuer's own
	// shape. Required.
	EntityID string
}

// TrustMarkIssueDependencies are a TrustMarkIssuer's injected
// collaborators. NewTrustMarkIssuer rejects a nil/zero value for every
// field — there is no implicit default signer or clock.
type TrustMarkIssueDependencies struct {
	// Signer produces every Trust Mark/Delegation's signature — this
	// entity's own federation signing key.
	Signer crypto.Signer

	// Algorithm Signer signs with.
	Algorithm fapi.SignatureAlgorithm

	// KeyID identifies Signer's key within this entity's own published
	// jwks — recorded in every Trust Mark/Delegation's "kid" header.
	// Required (unlike SelfIssueDependencies/SubordinateIssueDependencies'
	// own KeyID, which are optional there): OpenID Federation 1.0
	// §7.1/§7.2 both say a Trust Mark/Delegation JWT "MUST include the
	// kid header parameter."
	KeyID string

	Clock Clock
}

// TrustMarkIssuer signs Trust Marks (OpenID Federation 1.0 §7.1) and
// Trust Mark Delegations (§7.2). Construct one with NewTrustMarkIssuer.
//
// Like every other type in this package, TrustMarkIssuer is
// transport-agnostic: unlike Fetch/List (OpenID Federation 1.0 §9/§8.2,
// which SubjectFromFetchRequest/RejectUnsupportedListingFilters cover),
// there is no federation-defined HTTP endpoint for "issue me a Trust
// Mark" at all — issuance is an out-of-band administrative act (an
// entity applies for certification, an operator decides to grant it),
// so TrustMarkIssuer's own methods return plain errors, not a
// federation.Error: there is no request for the error's HTTPStatus to
// answer.
type TrustMarkIssuer struct {
	cfg  TrustMarkIssueConfig
	deps TrustMarkIssueDependencies
}

// NewTrustMarkIssuer validates cfg and deps and returns a
// TrustMarkIssuer.
func NewTrustMarkIssuer(cfg TrustMarkIssueConfig, deps TrustMarkIssueDependencies) (*TrustMarkIssuer, error) {
	if cfg.EntityID == "" {
		return nil, fmt.Errorf("federation: config: entity ID is required")
	}
	if err := ValidEntityID(cfg.EntityID); err != nil {
		return nil, fmt.Errorf("federation: config: %w", err)
	}
	if deps.Signer == nil {
		return nil, fmt.Errorf("federation: dependencies: signer is required")
	}
	if deps.KeyID == "" {
		return nil, fmt.Errorf("federation: dependencies: key id is required")
	}
	if deps.Clock == nil {
		return nil, fmt.Errorf("federation: dependencies: clock is required")
	}
	return &TrustMarkIssuer{cfg: cfg, deps: deps}, nil
}

// TrustMarkParams describes one Trust Mark to issue.
type TrustMarkParams struct {
	// Subject is the Entity this Trust Mark is about — the "sub" claim.
	// Required.
	Subject string

	// TrustMarkType is the "trust_mark_type" claim. Required.
	TrustMarkType string

	// Lifetime bounds how long the Trust Mark is valid for. Zero omits
	// the "exp" claim entirely — OpenID Federation 1.0 §7.1: "If not
	// present, it means that the Trust Mark does not expire," a real,
	// valid choice for a Trust Mark, unlike SelfIssueConfig/
	// SubordinateIssueConfig's own Lifetime (an Entity Statement's own
	// exp is never optional).
	Lifetime time.Duration

	// Delegation is a Trust Mark Delegation JWT (see TrustMarkIssuer.Delegation)
	// authorizing Config.EntityID to issue TrustMarkType — set this when
	// Config.EntityID is not itself the type's real owner (OpenID
	// Federation 1.0 §7.2). Leave empty when it is.
	Delegation string
}

// TrustMark signs and returns a Trust Mark (OpenID Federation 1.0 §7.1:
// iss == Config.EntityID) for p. The returned token is a
// trust-mark+jwt compact serialization, meant to be embedded verbatim
// in the subject's own Entity Configuration "trust_marks" claim (see
// SelfIssuer.EntityConfiguration's own metadata parameter) or handed to
// it out of band to embed itself.
func (i *TrustMarkIssuer) TrustMark(p TrustMarkParams) (string, error) {
	if p.Subject == "" {
		return "", fmt.Errorf("federation: trust mark: subject is required")
	}
	if err := ValidEntityID(p.Subject); err != nil {
		return "", fmt.Errorf("federation: trust mark: subject: %w", err)
	}
	if p.TrustMarkType == "" {
		return "", fmt.Errorf("federation: trust mark: trust mark type is required")
	}

	token, err := intfed.CreateTrustMark(intfed.CreateTrustMarkParams{
		Signer: i.deps.Signer, Algorithm: i.deps.Algorithm, KeyID: i.deps.KeyID,
		Issuer: i.cfg.EntityID, Subject: p.Subject, TrustMarkType: p.TrustMarkType,
		Now: i.deps.Clock.Now(), Lifetime: p.Lifetime, Delegation: p.Delegation,
	})
	if err != nil {
		return "", fmt.Errorf("federation: issue trust mark for %q: %w", p.Subject, err)
	}
	return token, nil
}

// DelegationParams describes one Trust Mark Delegation to issue.
type DelegationParams struct {
	// Subject is the Trust Mark Issuer being delegated to — the "sub"
	// claim. Required; must not equal Config.EntityID (an owner has no
	// need to delegate to itself — it can just call TrustMark directly
	// with no Delegation).
	Subject string

	// TrustMarkType is the "trust_mark_type" claim. Required.
	TrustMarkType string

	// Lifetime bounds how long the delegation is valid for. Zero omits
	// the "exp" claim entirely — OpenID Federation 1.0 §7.2: "If not
	// present, it means that the delegation does not expire."
	Lifetime time.Duration
}

// Delegation signs and returns a Trust Mark Delegation (OpenID
// Federation 1.0 §7.2: iss == Config.EntityID, the Trust Mark type's
// real owner) for p, authorizing p.Subject to issue Trust Marks of
// p.TrustMarkType on the owner's behalf. The returned token is a
// trust-mark-delegation+jwt compact serialization — hand it to
// p.Subject out of band so it can pass it as TrustMarkParams.Delegation
// on every Trust Mark it subsequently issues under this type.
func (i *TrustMarkIssuer) Delegation(p DelegationParams) (string, error) {
	if p.Subject == "" {
		return "", fmt.Errorf("federation: trust mark delegation: subject is required")
	}
	if err := ValidEntityID(p.Subject); err != nil {
		return "", fmt.Errorf("federation: trust mark delegation: subject: %w", err)
	}
	if p.Subject == i.cfg.EntityID {
		return "", fmt.Errorf("federation: trust mark delegation: subject must not equal the owner's own identifier")
	}
	if p.TrustMarkType == "" {
		return "", fmt.Errorf("federation: trust mark delegation: trust mark type is required")
	}

	token, err := intfed.CreateTrustMarkDelegation(intfed.CreateTrustMarkDelegationParams{
		Signer: i.deps.Signer, Algorithm: i.deps.Algorithm, KeyID: i.deps.KeyID,
		Issuer: i.cfg.EntityID, Subject: p.Subject, TrustMarkType: p.TrustMarkType,
		Now: i.deps.Clock.Now(), Lifetime: p.Lifetime,
	})
	if err != nil {
		return "", fmt.Errorf("federation: issue trust mark delegation for %q: %w", p.Subject, err)
	}
	return token, nil
}

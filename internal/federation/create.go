package federation

import (
	"crypto"
	"encoding/json"
	"fmt"
	"time"

	fapi "github.com/idfoundry/fapigo"
)

// CreateParams describes one Entity Statement to create — either an
// Entity Configuration (set Subject equal to Issuer) or a Subordinate
// Statement (set Subject to the immediate subordinate this statement is
// about). Create does not decide which variant this is; it only
// enforces that the two variants' own claims aren't mixed — see its own
// validation.
type CreateParams struct {
	// Signer produces the statement's signature — the issuing entity's
	// own federation key, never the subject's.
	Signer crypto.Signer

	// Algorithm the statement is signed with. Signer's key must match
	// it.
	Algorithm fapi.SignatureAlgorithm

	// KeyID, if non-empty, is recorded in the statement's "kid" header
	// so a verifier can select the right key from Issuer's own
	// published jwks without trial and error.
	KeyID string

	// Issuer is the "iss" claim — the entity issuing this statement.
	Issuer string

	// Subject is the "sub" claim — the entity this statement is about.
	// Equal to Issuer for an Entity Configuration; the immediate
	// subordinate's identifier for a Subordinate Statement.
	Subject string

	// Now is the statement's issuance time ("iat").
	Now time.Time

	// Lifetime bounds how long the statement is valid for (exp = Now +
	// Lifetime).
	Lifetime time.Duration

	// JWKS is the "jwks" claim: Issuer's own published federation
	// signing keys, already encoded as a JWK Set (RFC 7517 §5) JSON
	// object — e.g. the result of marshaling a keys.PublicKeySet. This
	// package builds no key material of its own; see doc.go for why
	// internal/ stays below keys in this module's dependency layering.
	JWKS json.RawMessage

	// Metadata is the "metadata" claim, if any — entity-type identifier
	// to that type's raw metadata object. Optional.
	Metadata map[string]json.RawMessage

	// AuthorityHints is the "authority_hints" claim — Issuer's own
	// immediate superiors. Only meaningful (and only accepted) when
	// Subject equals Issuer; see CreateParams' own doc comment.
	AuthorityHints []string

	// MetadataPolicy is the "metadata_policy" claim — the constraints
	// Issuer places on Subject's (and Subject's own subordinates')
	// metadata. Only meaningful (and only accepted) when Subject does
	// not equal Issuer.
	MetadataPolicy MetadataPolicy

	// MetadataPolicyCritical is the "metadata_policy_crit" claim. Only
	// meaningful (and only accepted) when Subject does not equal
	// Issuer.
	MetadataPolicyCritical []string

	// SourceEndpoint is the "source_endpoint" claim — the
	// federation_fetch_endpoint URL this statement is served from. Only
	// meaningful (and only accepted) when Subject does not equal
	// Issuer.
	SourceEndpoint string

	// Constraints is the "constraints" claim (OpenID Federation 1.0
	// §6.2) — restrictions Issuer places on Trust Chains passing
	// through it. Only meaningful (and only accepted) when Subject
	// does not equal Issuer.
	Constraints *Constraints

	// TrustMarks is the "trust_marks" claim (OpenID Federation 1.0 §7)
	// — Trust Marks Issuer holds about itself. Only meaningful (and
	// only accepted) when Subject equals Issuer (an Entity
	// Configuration); see doc.go's own "Trust Marks" section for what
	// this package does and does not do with one once parsed back.
	TrustMarks []RawTrustMark

	// TrustMarkOwners is the "trust_mark_owners" claim (OpenID
	// Federation 1.0 §7.2), keyed by trust_mark_type — set only by a
	// Trust Anchor, naming each Trust Mark type's real owner and that
	// owner's own keys. Only meaningful (and only accepted) when
	// Subject equals Issuer (an Entity Configuration).
	TrustMarkOwners map[string]TrustMarkOwner
}

// Create builds and signs an Entity Statement for p.
func Create(p CreateParams) (string, error) {
	if p.Signer == nil {
		return "", fmt.Errorf("federation: signer is nil")
	}
	if !p.Algorithm.IsValid() {
		return "", fmt.Errorf("federation: invalid algorithm %v", p.Algorithm)
	}
	if p.Issuer == "" {
		return "", fmt.Errorf("federation: issuer is empty")
	}
	if p.Subject == "" {
		return "", fmt.Errorf("federation: subject is empty")
	}
	if p.Now.IsZero() {
		return "", fmt.Errorf("federation: now is zero")
	}
	if p.Lifetime <= 0 {
		return "", fmt.Errorf("federation: lifetime must be positive")
	}
	if len(p.JWKS) == 0 {
		return "", fmt.Errorf("federation: jwks is empty")
	}

	selfSigned := p.Issuer == p.Subject
	if selfSigned && (p.MetadataPolicy != nil || p.MetadataPolicyCritical != nil || p.SourceEndpoint != "" || p.Constraints != nil) {
		return "", fmt.Errorf("federation: metadata_policy, metadata_policy_crit, source_endpoint and constraints are Subordinate Statement claims, but issuer equals subject (an Entity Configuration)")
	}
	if !selfSigned && p.AuthorityHints != nil {
		return "", fmt.Errorf("federation: authority_hints is an Entity Configuration claim, but issuer does not equal subject (a Subordinate Statement)")
	}
	if !selfSigned && p.TrustMarks != nil {
		return "", fmt.Errorf("federation: trust_marks is an Entity Configuration claim, but issuer does not equal subject (a Subordinate Statement)")
	}
	if !selfSigned && p.TrustMarkOwners != nil {
		return "", fmt.Errorf("federation: trust_mark_owners is an Entity Configuration claim, but issuer does not equal subject (a Subordinate Statement)")
	}

	claims := map[string]any{
		"iss":  p.Issuer,
		"sub":  p.Subject,
		"iat":  p.Now.Unix(),
		"exp":  p.Now.Add(p.Lifetime).Unix(),
		"jwks": json.RawMessage(p.JWKS),
	}
	if p.Metadata != nil {
		claims["metadata"] = p.Metadata
	}
	if p.AuthorityHints != nil {
		claims["authority_hints"] = p.AuthorityHints
	}
	if p.MetadataPolicy != nil {
		claims["metadata_policy"] = p.MetadataPolicy
	}
	if p.MetadataPolicyCritical != nil {
		claims["metadata_policy_crit"] = p.MetadataPolicyCritical
	}
	if p.SourceEndpoint != "" {
		claims["source_endpoint"] = p.SourceEndpoint
	}
	if p.Constraints != nil {
		claims["constraints"] = constraintsWireValue(*p.Constraints)
	}
	if p.TrustMarks != nil {
		trustMarks := make([]map[string]string, len(p.TrustMarks))
		for i, tm := range p.TrustMarks {
			trustMarks[i] = map[string]string{"trust_mark_type": tm.TrustMarkType, "trust_mark": tm.TrustMark}
		}
		claims["trust_marks"] = trustMarks
	}
	if p.TrustMarkOwners != nil {
		owners := make(map[string]map[string]any, len(p.TrustMarkOwners))
		for trustMarkType, o := range p.TrustMarkOwners {
			owners[trustMarkType] = map[string]any{"sub": o.Subject, "jwks": json.RawMessage(o.JWKS)}
		}
		claims["trust_mark_owners"] = owners
	}

	return signClaims(p.Signer, p.Algorithm, p.KeyID, jwtType, claims)
}

// constraintsWireValue builds the wire shape parseConstraints expects
// back — a plain map rather than a struct with json tags, so
// max_path_length is omitted entirely when HasMaxPathLength is false
// rather than round-tripping as an explicit 0 (a meaningfully
// different constraint; see Constraints' own doc comment).
func constraintsWireValue(c Constraints) map[string]any {
	out := map[string]any{}
	if c.HasMaxPathLength {
		out["max_path_length"] = c.MaxPathLength
	}
	if c.NamingConstraints != nil {
		nc := map[string]any{}
		if c.NamingConstraints.Permitted != nil {
			nc["permitted"] = c.NamingConstraints.Permitted
		}
		if c.NamingConstraints.Excluded != nil {
			nc["excluded"] = c.NamingConstraints.Excluded
		}
		out["naming_constraints"] = nc
	}
	if c.AllowedEntityTypes != nil {
		out["allowed_entity_types"] = c.AllowedEntityTypes
	}
	return out
}

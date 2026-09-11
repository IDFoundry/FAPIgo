package federation

import (
	"encoding/json"
	"fmt"
	"time"
)

// jwtType is the JWS "typ" header value every Entity Statement carries
// (OpenID Federation 1.0 §3.1/§3.2) — unlike internal/requestobject's
// own jwtType, this one is mandatory, not merely recommended; see
// ErrWrongType's own doc comment.
const jwtType = "entity-statement+jwt"

// PolicyOperators is one metadata claim's set of policy operators —
// operator name (e.g. "value", "subset_of") to its raw JSON argument.
// See ApplyPolicy.
type PolicyOperators map[string]json.RawMessage

// MetadataPolicy is a Subordinate Statement's "metadata_policy" claim:
// entity-type identifier (e.g. "openid_provider") to claim name (e.g.
// "id_token_signing_alg_values_supported") to that claim's
// PolicyOperators.
type MetadataPolicy map[string]map[string]PolicyOperators

// Claims is a parsed Entity Statement payload — the claims common to
// both an Entity Configuration (iss == sub, self-issued) and a
// Subordinate Statement (iss != sub, issued by an immediate superior
// about the entity named in sub), plus each variant's own claims. This
// package does not itself decide which variant a given Claims value
// is; a caller distinguishes by comparing Issuer and Subject, or by
// which fields it expects to be populated — the same "the JWT proves
// what it proves, policy decides what that means" split
// internal/requestobject's Claims already draws.
//
// Metadata is entity-type identifier to that type's raw metadata
// object — this package has no opinion on any entity type's own
// metadata schema (openid_provider, openid_relying_party,
// federation_entity, ...), matching the same "typed accessor over raw
// JSON, decided by the caller" precedent extension.Registry already
// uses for custom parameters.
//
// The "trust_mark_issuers" claim (OpenID Federation 1.0 §7) is
// deliberately not modeled here — see doc.go's own "Trust Marks"
// section for exactly what this package's Trust Mark support does and
// does not cover.
type Claims struct {
	Issuer  string
	Subject string

	IssuedAt  time.Time
	ExpiresAt time.Time

	// JWKS is the statement's raw "jwks" claim (a JWK Set, RFC 7517
	// §5) — the issuer's own published federation signing keys, unless
	// this is an Explicit Registration Response (not modeled by this
	// package yet; see doc.go), the one case OpenID Federation 1.0
	// §3.4 lets it be absent. Use jose.ParseJWKSet to resolve it into
	// usable keys; kept raw here rather than pre-parsed so a malformed
	// or unsupported entry in the set doesn't fail claims parsing
	// itself, mirroring jose.ParseJWKSet's own "one bad entry doesn't
	// invalidate the set" stance.
	JWKS json.RawMessage

	// Metadata is the statement's "metadata" claim, if present — nil
	// means the statement carries none (a Subordinate Statement that
	// only narrows via MetadataPolicy, without asserting metadata of
	// its own, is a normal shape).
	Metadata map[string]json.RawMessage

	// AuthorityHints is an Entity Configuration's own "authority_hints"
	// claim: the entity's immediate superiors, in no particular
	// preference order (OpenID Federation 1.0 §3.1). Empty for a Trust
	// Anchor (which has none) and for any statement that isn't an
	// Entity Configuration.
	AuthorityHints []string

	// MetadataPolicy is a Subordinate Statement's own "metadata_policy"
	// claim — nil for an Entity Configuration, and a normal (not an
	// error) absence for a Subordinate Statement that doesn't
	// constrain its subordinate's metadata at all.
	MetadataPolicy MetadataPolicy

	// MetadataPolicyCritical is a Subordinate Statement's own
	// "metadata_policy_crit" claim (OpenID Federation 1.0 §3.1.3) —
	// non-standard policy operator names that MUST be understood and
	// processed; see ApplyPolicy and MergePolicy.
	MetadataPolicyCritical []string

	// SourceEndpoint is a Subordinate Statement's own "source_endpoint"
	// claim — the federation_fetch_endpoint URL this statement was (or
	// should be) fetched from, echoed back so a resolver can detect a
	// statement served from somewhere other than where it claims to
	// come from.
	SourceEndpoint string

	// Constraints is a Subordinate Statement's own "constraints" claim
	// (OpenID Federation 1.0 §6.2) — nil for an Entity Configuration,
	// and a normal (not an error) absence for a Subordinate Statement
	// that sets none.
	Constraints *Constraints

	// TrustMarks is an Entity Configuration's own "trust_marks" claim
	// (OpenID Federation 1.0 §7) — nil for a Subordinate Statement, and
	// a normal (not an error) absence for an Entity Configuration that
	// declares none. Each entry's own "trust_mark" JWT is retained raw,
	// unparsed and unverified — see doc.go's own "Trust Marks" section
	// for how a caller establishes trust in one.
	TrustMarks []RawTrustMark

	// TrustMarkOwners is an Entity Configuration's own "trust_mark_owners"
	// claim (OpenID Federation 1.0 §7.2), keyed by trust_mark_type — nil
	// for a Subordinate Statement, and a normal (not an error) absence
	// for an Entity Configuration that declares none. A Trust Anchor
	// publishes this to name, for a given Trust Mark type, both the
	// type's real owner and that owner's own keys (published directly
	// here, not resolved via a separate Trust Chain the way a Trust
	// Mark Issuer's keys are) — used to validate a "delegation" claim on
	// a Trust Mark of that type; see doc.go's own "Trust Marks" section.
	TrustMarkOwners map[string]TrustMarkOwner
}

// RawTrustMark is one entry of an Entity Configuration's own
// "trust_marks" claim — the wrapper object's own "trust_mark_type" and
// "trust_mark" (a signed Trust Mark JWT) members, exactly as published,
// before ParseTrustMark or any trust decision is made about them.
type RawTrustMark struct {
	TrustMarkType string
	TrustMark     string
}

// TrustMarkOwner is one entry of an Entity Configuration's own
// "trust_mark_owners" claim (OpenID Federation 1.0 §7.2) — a Trust
// Mark type's real owner (Subject) and that owner's own JWK Set
// (JWKS), published directly by the Trust Anchor rather than resolved
// via a separate Trust Chain.
type TrustMarkOwner struct {
	Subject string
	JWKS    json.RawMessage
}

// Constraints is a Subordinate Statement's "constraints" claim (OpenID
// Federation 1.0 §6.2) — restrictions a superior places on the Trust
// Chains that may pass through it. A resolver (outside this package;
// see doc.go) is responsible for actually enforcing these while
// walking a chain; this package only parses them.
type Constraints struct {
	// MaxPathLength is the "max_path_length" constraint — the maximum
	// number of Intermediate Entities allowed between the entity
	// setting this constraint and the Trust Chain subject. Zero is a
	// meaningful value ("no Intermediates may appear"), distinct from
	// the constraint being absent — see HasMaxPathLength.
	MaxPathLength    int
	HasMaxPathLength bool

	// NamingConstraints is the "naming_constraints" constraint, if any —
	// restrictions on Subordinate Entity Identifiers' host names, in
	// RFC 5280 §4.2.1.10 domain-name-constraint syntax.
	NamingConstraints *NamingConstraints

	// AllowedEntityTypes is the "allowed_entity_types" constraint, if
	// any — nil means the claim was absent (no constraint; any Entity
	// Type is allowed); a non-nil, empty slice means the claim was
	// present as an empty array (OpenID Federation 1.0 §6.2.3: only the
	// federation_entity Entity Type — which this constraint MUST NOT
	// itself list, and which is always allowed regardless — is
	// permitted).
	AllowedEntityTypes []string
}

// NamingConstraints is Constraints' own "naming_constraints" member.
type NamingConstraints struct {
	Permitted []string
	Excluded  []string
}

func parseClaims(payload []byte) (Claims, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil {
		return Claims{}, fmt.Errorf("%w: %v", ErrMalformedClaims, err)
	}

	iss, err := popRequiredString(raw, "iss")
	if err != nil {
		return Claims{}, err
	}
	sub, err := popRequiredString(raw, "sub")
	if err != nil {
		return Claims{}, err
	}
	iat, err := popRequiredInt64(raw, "iat")
	if err != nil {
		return Claims{}, err
	}
	exp, err := popRequiredInt64(raw, "exp")
	if err != nil {
		return Claims{}, err
	}
	jwks, hasJWKS := raw["jwks"]
	if !hasJWKS {
		return Claims{}, fmt.Errorf("%w: missing \"jwks\"", ErrMalformedClaims)
	}
	delete(raw, "jwks")

	c := Claims{
		Issuer:    iss,
		Subject:   sub,
		IssuedAt:  time.Unix(iat, 0),
		ExpiresAt: time.Unix(exp, 0),
		JWKS:      jwks,
	}

	if metadataRaw, ok := raw["metadata"]; ok {
		var metadata map[string]json.RawMessage
		if err := json.Unmarshal(metadataRaw, &metadata); err != nil {
			return Claims{}, fmt.Errorf("%w: metadata: %v", ErrMalformedClaims, err)
		}
		c.Metadata = metadata
	}
	if hintsRaw, ok := raw["authority_hints"]; ok {
		var hints []string
		if err := json.Unmarshal(hintsRaw, &hints); err != nil {
			return Claims{}, fmt.Errorf("%w: authority_hints: %v", ErrMalformedClaims, err)
		}
		c.AuthorityHints = hints
	}
	if policyRaw, ok := raw["metadata_policy"]; ok {
		var policy MetadataPolicy
		if err := json.Unmarshal(policyRaw, &policy); err != nil {
			return Claims{}, fmt.Errorf("%w: metadata_policy: %v", ErrMalformedClaims, err)
		}
		c.MetadataPolicy = policy
	}
	if critRaw, ok := raw["metadata_policy_crit"]; ok {
		var crit []string
		if err := json.Unmarshal(critRaw, &crit); err != nil {
			return Claims{}, fmt.Errorf("%w: metadata_policy_crit: %v", ErrMalformedClaims, err)
		}
		c.MetadataPolicyCritical = crit
	}
	if sourceRaw, ok := raw["source_endpoint"]; ok {
		var source string
		if err := json.Unmarshal(sourceRaw, &source); err != nil {
			return Claims{}, fmt.Errorf("%w: source_endpoint: %v", ErrMalformedClaims, err)
		}
		c.SourceEndpoint = source
	}
	if constraintsRaw, ok := raw["constraints"]; ok {
		constraints, err := parseConstraints(constraintsRaw)
		if err != nil {
			return Claims{}, fmt.Errorf("%w: constraints: %v", ErrMalformedClaims, err)
		}
		c.Constraints = &constraints
	}
	if trustMarksRaw, ok := raw["trust_marks"]; ok {
		var trustMarks []struct {
			TrustMarkType string `json:"trust_mark_type"`
			TrustMark     string `json:"trust_mark"`
		}
		if err := json.Unmarshal(trustMarksRaw, &trustMarks); err != nil {
			return Claims{}, fmt.Errorf("%w: trust_marks: %v", ErrMalformedClaims, err)
		}
		c.TrustMarks = make([]RawTrustMark, len(trustMarks))
		for i, tm := range trustMarks {
			if tm.TrustMarkType == "" || tm.TrustMark == "" {
				return Claims{}, fmt.Errorf("%w: trust_marks[%d]: trust_mark_type and trust_mark are both required", ErrMalformedClaims, i)
			}
			c.TrustMarks[i] = RawTrustMark{TrustMarkType: tm.TrustMarkType, TrustMark: tm.TrustMark}
		}
	}
	if ownersRaw, ok := raw["trust_mark_owners"]; ok {
		var owners map[string]struct {
			Subject string          `json:"sub"`
			JWKS    json.RawMessage `json:"jwks"`
		}
		if err := json.Unmarshal(ownersRaw, &owners); err != nil {
			return Claims{}, fmt.Errorf("%w: trust_mark_owners: %v", ErrMalformedClaims, err)
		}
		c.TrustMarkOwners = make(map[string]TrustMarkOwner, len(owners))
		for trustMarkType, o := range owners {
			if o.Subject == "" || len(o.JWKS) == 0 {
				return Claims{}, fmt.Errorf("%w: trust_mark_owners[%q]: sub and jwks are both required", ErrMalformedClaims, trustMarkType)
			}
			c.TrustMarkOwners[trustMarkType] = TrustMarkOwner{Subject: o.Subject, JWKS: o.JWKS}
		}
	}

	return c, nil
}

func parseConstraints(payload json.RawMessage) (Constraints, error) {
	var raw struct {
		MaxPathLength     *int `json:"max_path_length"`
		NamingConstraints *struct {
			Permitted []string `json:"permitted"`
			Excluded  []string `json:"excluded"`
		} `json:"naming_constraints"`
		AllowedEntityTypes []string `json:"allowed_entity_types"`
	}
	if err := json.Unmarshal(payload, &raw); err != nil {
		return Constraints{}, err
	}
	c := Constraints{AllowedEntityTypes: raw.AllowedEntityTypes}
	if raw.MaxPathLength != nil {
		if *raw.MaxPathLength < 0 {
			return Constraints{}, fmt.Errorf("max_path_length must not be negative")
		}
		c.MaxPathLength = *raw.MaxPathLength
		c.HasMaxPathLength = true
	}
	if raw.NamingConstraints != nil {
		c.NamingConstraints = &NamingConstraints{Permitted: raw.NamingConstraints.Permitted, Excluded: raw.NamingConstraints.Excluded}
	}
	return c, nil
}

func popRequiredString(m map[string]json.RawMessage, key string) (string, error) {
	raw, ok := m[key]
	if !ok {
		return "", fmt.Errorf("%w: missing %q", ErrMalformedClaims, key)
	}
	delete(m, key)
	var s string
	if err := json.Unmarshal(raw, &s); err != nil || s == "" {
		return "", fmt.Errorf("%w: %q must be a non-empty string", ErrMalformedClaims, key)
	}
	return s, nil
}

func popRequiredInt64(m map[string]json.RawMessage, key string) (int64, error) {
	raw, ok := m[key]
	if !ok {
		return 0, fmt.Errorf("%w: missing %q", ErrMalformedClaims, key)
	}
	delete(m, key)
	var n int64
	if err := json.Unmarshal(raw, &n); err != nil {
		return 0, fmt.Errorf("%w: %q must be an integer", ErrMalformedClaims, key)
	}
	return n, nil
}

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
// Trust Marks (OpenID Federation 1.0 §7 — the "trust_marks",
// "trust_mark_issuers" and "trust_mark_owners" claims) are
// deliberately not modeled here: nothing in this package's current
// scope (Entity Statement create/verify, metadata policy application)
// reads them. A caller that needs to inspect them today can still
// reach the statement's raw payload before it's discarded; a later
// revision adds typed accessors once something actually consumes them,
// rather than modeling them speculatively now.
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

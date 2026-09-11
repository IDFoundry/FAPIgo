package federation

import (
	"crypto"
	"encoding/json"
	"fmt"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
)

// trustMarkJWTType is the JWS "typ" header value every Trust Mark JWT
// MUST carry (OpenID Federation 1.0 §7: "Trust Mark JWTs MUST be
// explicitly typed... The typ header parameter value MUST be
// trust-mark+jwt unless the trust framework in use defines a more
// specific media type value"). This package only recognizes the
// generic value — a framework-specific typ is out of this first
// version's scope; see doc.go.
const trustMarkJWTType = "trust-mark+jwt"

// TrustMarkClaims is a parsed Trust Mark JWT payload (OpenID Federation
// 1.0 §7.1).
type TrustMarkClaims struct {
	Issuer        string
	Subject       string
	TrustMarkType string
	IssuedAt      time.Time

	// ExpiresAt is zero if the "exp" claim was absent — per §7.1, "If
	// not present, it means that the Trust Mark does not expire."
	// Unlike an Entity Statement's own ExpiresAt (always required),
	// this is a normal, valid absence, not an error.
	ExpiresAt time.Time

	// Delegation is the Trust Mark's own unverified "delegation" claim
	// (OpenID Federation 1.0 §7.2) — "" if absent, a normal shape for a
	// Trust Mark whose Issuer is also its type's owner. Its value is a
	// Trust Mark Delegation JWT; parse it with ParseTrustMarkDelegation.
	Delegation string
}

// TrustMark is a parsed, but not yet signature-verified, Trust Mark
// JWT — the same "claims safe to read as lookup keys, never as a basis
// for trust until Verify succeeds" contract Statement and
// internal/requestobject.Object already establish.
type TrustMark struct {
	compact jose.Compact
	claims  TrustMarkClaims
}

// ParseTrustMark parses token without verifying its signature.
func ParseTrustMark(token string) (TrustMark, error) {
	compact, err := jose.ParseCompact(token)
	if err != nil {
		return TrustMark{}, fmt.Errorf("federation: %w", err)
	}
	if compact.Header.Type != trustMarkJWTType {
		return TrustMark{}, ErrTrustMarkWrongType
	}
	claims, err := parseTrustMarkClaims(compact.Payload)
	if err != nil {
		return TrustMark{}, err
	}
	return TrustMark{compact: compact, claims: claims}, nil
}

// KeyID returns the Trust Mark header's "kid", or "" if absent.
// Untrusted until Verify succeeds; use only to select which of the
// issuer's published keys to verify against.
func (tm TrustMark) KeyID() string { return tm.compact.Header.KeyID }

// Algorithm returns the algorithm the Trust Mark header claims to use.
// Untrusted until Verify succeeds — a caller must still supply the
// algorithm it expects via TrustMarkVerifyPolicy rather than trusting
// this value, exactly as jose.Compact.Verify requires.
func (tm TrustMark) Algorithm() fapi.SignatureAlgorithm { return tm.compact.Header.Algorithm }

// ClaimedIssuer returns the Trust Mark's unverified "iss" claim — the
// Trust Mark Issuer whose own Trust Chain a caller (a federation.Resolver,
// most notably) must independently resolve before this value can be
// used to select a key to verify against (OpenID Federation 1.0 §7's
// own "the trust in the Trust Mark Issuer comes before the trust in
// the trust mark").
func (tm TrustMark) ClaimedIssuer() string { return tm.claims.Issuer }

// ClaimedSubject returns the Trust Mark's unverified "sub" claim, for
// use as a lookup key only.
func (tm TrustMark) ClaimedSubject() string { return tm.claims.Subject }

// ClaimedTrustMarkType returns the Trust Mark's unverified
// "trust_mark_type" claim, for use as a lookup key only.
func (tm TrustMark) ClaimedTrustMarkType() string { return tm.claims.TrustMarkType }

// ClaimedDelegation returns the Trust Mark's unverified "delegation"
// claim, or "" if absent — a Trust Mark Delegation JWT to parse with
// ParseTrustMarkDelegation and validate once the caller knows (from the
// Trust Anchor's own "trust_mark_owners" claim) who this Trust Mark
// type's real owner is.
func (tm TrustMark) ClaimedDelegation() string { return tm.claims.Delegation }

// TrustMarkVerifyPolicy is the set of checks Verify enforces against a
// TrustMark.
type TrustMarkVerifyPolicy struct {
	// ExpectedSubject is the Entity Identifier of the Entity whose
	// Entity Configuration declared this Trust Mark — the Trust Mark's
	// sub claim must equal it exactly (OpenID Federation 1.0 §7.3 step
	// 4: "The Entity Identifier of the Entity whose Entity Configuration
	// contains the instance MUST match the value of the Claim sub").
	ExpectedSubject string

	// ExpectedTrustMarkType is the trust_mark_type the wrapper
	// RawTrustMark declared this instance under — the Trust Mark's own
	// trust_mark_type claim must equal it exactly (OpenID Federation
	// 1.0 §5's own cross-check between the two).
	ExpectedTrustMarkType string

	// Algorithm is the algorithm the Trust Mark Issuer is registered or
	// discovered to sign with. The Trust Mark header's algorithm must
	// equal it exactly — this is what prevents algorithm-confusion
	// attacks, so it must come from the issuer's own published jwks
	// (via its kid), never trusted from the Trust Mark itself.
	Algorithm fapi.SignatureAlgorithm

	// Now is the time to validate iat/exp against.
	Now time.Time

	// MaxClockSkew bounds how far in the future an iat claim may be, and
	// extends how long past exp a Trust Mark is still accepted. Zero
	// means no tolerance.
	MaxClockSkew time.Duration
}

// Verify checks tm's signature against pub and its claims against
// policy, returning the Trust Mark's now-trusted claims. It does not
// itself validate a "delegation" claim (OpenID Federation 1.0 §7.2) —
// that requires knowing, from the Trust Anchor's own
// "trust_mark_owners" claim, whether one is even required for this
// Trust Mark's own type, which is a caller concern (a
// federation.Resolver, most notably); see ClaimedDelegation and
// TrustMarkDelegation.
func (tm TrustMark) Verify(pub crypto.PublicKey, policy TrustMarkVerifyPolicy) (TrustMarkClaims, error) {
	if policy.ExpectedSubject == "" {
		return TrustMarkClaims{}, fmt.Errorf("federation: ExpectedSubject is empty")
	}
	if policy.ExpectedTrustMarkType == "" {
		return TrustMarkClaims{}, fmt.Errorf("federation: ExpectedTrustMarkType is empty")
	}
	if policy.Now.IsZero() {
		return TrustMarkClaims{}, fmt.Errorf("federation: Now is zero")
	}

	if err := tm.compact.Verify(pub, policy.Algorithm); err != nil {
		return TrustMarkClaims{}, fmt.Errorf("federation: %w", err)
	}
	c := tm.claims

	if c.Subject != policy.ExpectedSubject {
		return TrustMarkClaims{}, ErrSubjectMismatch
	}
	if c.TrustMarkType != policy.ExpectedTrustMarkType {
		return TrustMarkClaims{}, ErrTrustMarkTypeMismatch
	}
	if policy.Now.Before(c.IssuedAt.Add(-policy.MaxClockSkew)) {
		return TrustMarkClaims{}, ErrTrustMarkNotYetValid
	}
	if !c.ExpiresAt.IsZero() && policy.Now.After(c.ExpiresAt.Add(policy.MaxClockSkew)) {
		return TrustMarkClaims{}, ErrTrustMarkExpired
	}

	return c, nil
}

func parseTrustMarkClaims(payload []byte) (TrustMarkClaims, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil {
		return TrustMarkClaims{}, fmt.Errorf("%w: %v", ErrMalformedClaims, err)
	}

	iss, err := popRequiredString(raw, "iss")
	if err != nil {
		return TrustMarkClaims{}, err
	}
	sub, err := popRequiredString(raw, "sub")
	if err != nil {
		return TrustMarkClaims{}, err
	}
	trustMarkType, err := popRequiredString(raw, "trust_mark_type")
	if err != nil {
		return TrustMarkClaims{}, err
	}
	iat, err := popRequiredInt64(raw, "iat")
	if err != nil {
		return TrustMarkClaims{}, err
	}

	c := TrustMarkClaims{
		Issuer: iss, Subject: sub, TrustMarkType: trustMarkType,
		IssuedAt: time.Unix(iat, 0),
	}
	if expRaw, ok := raw["exp"]; ok {
		var exp int64
		if err := json.Unmarshal(expRaw, &exp); err != nil {
			return TrustMarkClaims{}, fmt.Errorf("%w: %q must be an integer", ErrMalformedClaims, "exp")
		}
		c.ExpiresAt = time.Unix(exp, 0)
	}
	if delegationRaw, ok := raw["delegation"]; ok {
		var delegation string
		if err := json.Unmarshal(delegationRaw, &delegation); err != nil || delegation == "" {
			return TrustMarkClaims{}, fmt.Errorf("%w: %q must be a non-empty string", ErrMalformedClaims, "delegation")
		}
		c.Delegation = delegation
	}
	return c, nil
}

// trustMarkDelegationJWTType is the JWS "typ" header value every Trust
// Mark Delegation JWT MUST carry (OpenID Federation 1.0 §7.2: "MUST be
// explicitly typed, by setting the typ header parameter to
// trust-mark-delegation+jwt... Trust Mark delegation JWTs without a typ
// header parameter or with a different typ value MUST be rejected").
const trustMarkDelegationJWTType = "trust-mark-delegation+jwt"

// TrustMarkDelegationClaims is a parsed Trust Mark Delegation JWT
// payload (OpenID Federation 1.0 §7.2) — a Trust Mark type's owner
// (Issuer) authorizing another entity (Subject) to issue Trust Marks of
// that type.
type TrustMarkDelegationClaims struct {
	Issuer        string
	Subject       string
	TrustMarkType string
	IssuedAt      time.Time

	// ExpiresAt is zero if the "exp" claim was absent — per §7.2, "If
	// not present, it means that the delegation does not expire."
	ExpiresAt time.Time
}

// TrustMarkDelegation is a parsed, but not yet signature-verified,
// Trust Mark Delegation JWT — the same "claims safe to read as lookup
// keys, never as a basis for trust until Verify succeeds" contract
// TrustMark itself establishes.
type TrustMarkDelegation struct {
	compact jose.Compact
	claims  TrustMarkDelegationClaims
}

// ParseTrustMarkDelegation parses token without verifying its
// signature.
func ParseTrustMarkDelegation(token string) (TrustMarkDelegation, error) {
	compact, err := jose.ParseCompact(token)
	if err != nil {
		return TrustMarkDelegation{}, fmt.Errorf("federation: %w", err)
	}
	if compact.Header.Type != trustMarkDelegationJWTType {
		return TrustMarkDelegation{}, ErrTrustMarkDelegationWrongType
	}
	claims, err := parseTrustMarkDelegationClaims(compact.Payload)
	if err != nil {
		return TrustMarkDelegation{}, err
	}
	return TrustMarkDelegation{compact: compact, claims: claims}, nil
}

// KeyID returns the delegation header's "kid", or "" if absent.
// Untrusted until Verify succeeds; use only to select which of the
// owner's published keys to verify against.
func (d TrustMarkDelegation) KeyID() string { return d.compact.Header.KeyID }

// Algorithm returns the algorithm the delegation header claims to use.
// Untrusted until Verify succeeds — a caller must still supply the
// algorithm it expects via TrustMarkDelegationVerifyPolicy rather than
// trusting this value, exactly as jose.Compact.Verify requires.
func (d TrustMarkDelegation) Algorithm() fapi.SignatureAlgorithm { return d.compact.Header.Algorithm }

// ClaimedIssuer returns the delegation's unverified "iss" claim — the
// Trust Mark type's claimed owner. A caller must independently know
// (from the Trust Anchor's own "trust_mark_owners" claim, never from
// this value) the real owner's identity and keys before this can be
// used for anything.
func (d TrustMarkDelegation) ClaimedIssuer() string { return d.claims.Issuer }

// ClaimedSubject returns the delegation's unverified "sub" claim, for
// use as a lookup key only.
func (d TrustMarkDelegation) ClaimedSubject() string { return d.claims.Subject }

// ClaimedTrustMarkType returns the delegation's unverified
// "trust_mark_type" claim, for use as a lookup key only.
func (d TrustMarkDelegation) ClaimedTrustMarkType() string { return d.claims.TrustMarkType }

// TrustMarkDelegationVerifyPolicy is the set of checks Verify enforces
// against a TrustMarkDelegation.
type TrustMarkDelegationVerifyPolicy struct {
	// ExpectedIssuer is the Trust Mark type's real owner, as named by
	// the Trust Anchor's own "trust_mark_owners" claim — the
	// delegation's iss claim must equal it exactly (OpenID Federation
	// 1.0 §7.2's own validation step 5: "The Entity Identifier of the
	// Trust Mark Owner MUST match the value of iss in the delegation").
	ExpectedIssuer string

	// ExpectedSubject is the Trust Mark Issuer being delegated to — the
	// delegation's sub claim must equal it exactly (§7.2's own step 4:
	// "The Entity Identifier of the Trust Mark Issuer MUST match the
	// value of sub in the delegation").
	ExpectedSubject string

	// ExpectedTrustMarkType is the Trust Mark's own trust_mark_type —
	// the delegation's trust_mark_type claim must equal it exactly
	// (§7.2's own step 7).
	ExpectedTrustMarkType string

	// Algorithm is the algorithm the Trust Mark Owner is registered or
	// discovered to sign with. The delegation header's algorithm must
	// equal it exactly — this is what prevents algorithm-confusion
	// attacks, so it must come from the owner's own published jwks (via
	// its kid), never trusted from the delegation itself.
	Algorithm fapi.SignatureAlgorithm

	// Now is the time to validate iat/exp against.
	Now time.Time

	// MaxClockSkew bounds how far in the future an iat claim may be, and
	// extends how long past exp a delegation is still accepted. Zero
	// means no tolerance.
	MaxClockSkew time.Duration
}

// Verify checks d's signature against pub and its claims against
// policy, returning the delegation's now-trusted claims.
func (d TrustMarkDelegation) Verify(pub crypto.PublicKey, policy TrustMarkDelegationVerifyPolicy) (TrustMarkDelegationClaims, error) {
	if policy.ExpectedIssuer == "" {
		return TrustMarkDelegationClaims{}, fmt.Errorf("federation: ExpectedIssuer is empty")
	}
	if policy.ExpectedSubject == "" {
		return TrustMarkDelegationClaims{}, fmt.Errorf("federation: ExpectedSubject is empty")
	}
	if policy.ExpectedTrustMarkType == "" {
		return TrustMarkDelegationClaims{}, fmt.Errorf("federation: ExpectedTrustMarkType is empty")
	}
	if policy.Now.IsZero() {
		return TrustMarkDelegationClaims{}, fmt.Errorf("federation: Now is zero")
	}

	if err := d.compact.Verify(pub, policy.Algorithm); err != nil {
		return TrustMarkDelegationClaims{}, fmt.Errorf("federation: %w", err)
	}
	c := d.claims

	if c.Issuer != policy.ExpectedIssuer {
		return TrustMarkDelegationClaims{}, ErrIssuerMismatch
	}
	if c.Subject != policy.ExpectedSubject {
		return TrustMarkDelegationClaims{}, ErrSubjectMismatch
	}
	if c.TrustMarkType != policy.ExpectedTrustMarkType {
		return TrustMarkDelegationClaims{}, ErrTrustMarkDelegationTypeMismatch
	}
	if policy.Now.Before(c.IssuedAt.Add(-policy.MaxClockSkew)) {
		return TrustMarkDelegationClaims{}, ErrTrustMarkDelegationNotYetValid
	}
	if !c.ExpiresAt.IsZero() && policy.Now.After(c.ExpiresAt.Add(policy.MaxClockSkew)) {
		return TrustMarkDelegationClaims{}, ErrTrustMarkDelegationExpired
	}

	return c, nil
}

func parseTrustMarkDelegationClaims(payload []byte) (TrustMarkDelegationClaims, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil {
		return TrustMarkDelegationClaims{}, fmt.Errorf("%w: %v", ErrMalformedClaims, err)
	}

	iss, err := popRequiredString(raw, "iss")
	if err != nil {
		return TrustMarkDelegationClaims{}, err
	}
	sub, err := popRequiredString(raw, "sub")
	if err != nil {
		return TrustMarkDelegationClaims{}, err
	}
	trustMarkType, err := popRequiredString(raw, "trust_mark_type")
	if err != nil {
		return TrustMarkDelegationClaims{}, err
	}
	iat, err := popRequiredInt64(raw, "iat")
	if err != nil {
		return TrustMarkDelegationClaims{}, err
	}

	c := TrustMarkDelegationClaims{
		Issuer: iss, Subject: sub, TrustMarkType: trustMarkType,
		IssuedAt: time.Unix(iat, 0),
	}
	if expRaw, ok := raw["exp"]; ok {
		var exp int64
		if err := json.Unmarshal(expRaw, &exp); err != nil {
			return TrustMarkDelegationClaims{}, fmt.Errorf("%w: %q must be an integer", ErrMalformedClaims, "exp")
		}
		c.ExpiresAt = time.Unix(exp, 0)
	}
	return c, nil
}

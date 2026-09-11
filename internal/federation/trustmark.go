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
// policy, returning the Trust Mark's now-trusted claims. This first
// version does not validate a "delegation" claim (OpenID Federation
// 1.0 §7.2) — see doc.go's own "Trust Marks" section.
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
	return c, nil
}

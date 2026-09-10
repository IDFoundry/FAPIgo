package federation

import (
	"crypto"
	"fmt"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
)

// Statement is a parsed, but not yet signature-verified, Entity
// Statement. Its accessors are untrusted lookup keys only — exactly
// internal/requestobject.Object's own contract — never a basis for a
// trust decision until Verify succeeds. In particular, ClaimedAuthorityHints
// exists specifically so a trust-chain resolver (outside this package;
// see doc.go) can decide which superior's Entity Configuration to fetch
// next before it has any reason yet to trust this statement's claims —
// the superior's own signature on the resulting Subordinate Statement
// is what actually establishes the hint was honest.
type Statement struct {
	compact jose.Compact
	claims  Claims
}

// Parse parses an Entity Statement without verifying its signature.
func Parse(token string) (Statement, error) {
	compact, err := jose.ParseCompact(token)
	if err != nil {
		return Statement{}, fmt.Errorf("federation: %w", err)
	}
	if compact.Header.Type != jwtType {
		return Statement{}, ErrWrongType
	}
	claims, err := parseClaims(compact.Payload)
	if err != nil {
		return Statement{}, err
	}
	return Statement{compact: compact, claims: claims}, nil
}

// KeyID returns the statement header's "kid", or "" if absent.
// Untrusted until Verify succeeds; use only to select which of the
// issuer's published keys to verify against.
func (s Statement) KeyID() string { return s.compact.Header.KeyID }

// Algorithm returns the algorithm the statement header claims to use.
// Untrusted until Verify succeeds — a caller must still supply the
// algorithm it expects via VerifyPolicy rather than trusting this
// value, exactly as jose.Compact.Verify requires.
func (s Statement) Algorithm() fapi.SignatureAlgorithm { return s.compact.Header.Algorithm }

// ClaimedIssuer returns the statement's unverified "iss" claim, for use
// as a lookup key only (e.g. which entity's published keys to resolve
// candidates from).
func (s Statement) ClaimedIssuer() string { return s.claims.Issuer }

// ClaimedSubject returns the statement's unverified "sub" claim, for
// use as a lookup key only.
func (s Statement) ClaimedSubject() string { return s.claims.Subject }

// ClaimedAuthorityHints returns the statement's unverified
// "authority_hints" claim, for use as a lookup key only — see
// Statement's own doc comment for why this is safe to act on before
// Verify succeeds.
func (s Statement) ClaimedAuthorityHints() []string { return s.claims.AuthorityHints }

// VerifyPolicy is the set of checks Verify enforces against a
// Statement.
type VerifyPolicy struct {
	// ExpectedIssuer is the entity the caller is trying to authenticate
	// as having issued this statement — the statement's iss claim must
	// equal it exactly. For an Entity Configuration this is the
	// entity's own identifier; for a Subordinate Statement it's whichever
	// superior's federation_fetch_endpoint (or federation_list_endpoint)
	// this statement was fetched from.
	ExpectedIssuer string

	// ExpectedSubject is the entity this statement is expected to be
	// about — the statement's sub claim must equal it exactly. Equal to
	// ExpectedIssuer for an Entity Configuration.
	ExpectedSubject string

	// Algorithm is the algorithm ExpectedIssuer is registered or
	// discovered to sign with. The statement header's algorithm must
	// equal it exactly — this is what prevents algorithm-confusion
	// attacks, so it must come from the issuer's own published jwks
	// (via its kid), never trusted from the statement itself.
	Algorithm fapi.SignatureAlgorithm

	// Now is the time to validate iat/exp against.
	Now time.Time

	// MaxLifetime bounds how far in the future (relative to Now) the
	// statement's exp claim may be. Required — there is no implicit
	// default.
	MaxLifetime time.Duration

	// MaxClockSkew bounds how far in the future (relative to Now) an
	// iat claim may be, and extends how long past exp a statement is
	// still accepted. Zero means no tolerance.
	MaxClockSkew time.Duration
}

// Verify checks s's signature against pub and its claims against
// policy, returning the statement's now-trusted Claims.
func (s Statement) Verify(pub crypto.PublicKey, policy VerifyPolicy) (Claims, error) {
	if policy.ExpectedIssuer == "" {
		return Claims{}, fmt.Errorf("federation: ExpectedIssuer is empty")
	}
	if policy.ExpectedSubject == "" {
		return Claims{}, fmt.Errorf("federation: ExpectedSubject is empty")
	}
	if policy.Now.IsZero() {
		return Claims{}, fmt.Errorf("federation: Now is zero")
	}
	if policy.MaxLifetime <= 0 {
		return Claims{}, fmt.Errorf("federation: MaxLifetime must be positive")
	}

	if err := s.compact.Verify(pub, policy.Algorithm); err != nil {
		return Claims{}, fmt.Errorf("federation: %w", err)
	}
	c := s.claims

	if c.Issuer != policy.ExpectedIssuer {
		return Claims{}, ErrIssuerMismatch
	}
	if c.Subject != policy.ExpectedSubject {
		return Claims{}, ErrSubjectMismatch
	}

	if policy.Now.After(c.ExpiresAt.Add(policy.MaxClockSkew)) {
		return Claims{}, ErrExpired
	}
	if c.ExpiresAt.Sub(policy.Now) > policy.MaxLifetime {
		return Claims{}, ErrLifetimeExceeded
	}
	if policy.Now.Before(c.IssuedAt.Add(-policy.MaxClockSkew)) {
		return Claims{}, ErrNotYetValid
	}

	return c, nil
}

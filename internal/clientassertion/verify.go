package clientassertion

import (
	"context"
	"crypto"
	"fmt"
	"slices"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
)

// ReplayChecker records that a client assertion's "jti" has been used,
// failing if it has been seen before. As with dpop.ReplayChecker,
// implementations are expected to key storage by a namespaced digest of
// jti, not the raw value — that adaptation is the caller's
// responsibility so this package stays decoupled from a specific storage
// contract.
type ReplayChecker interface {
	UseOnce(ctx context.Context, jti string, expiresAt time.Time) error
}

// Assertion is a parsed, but not yet signature-verified, client
// assertion. KeyID, Algorithm, ClaimedIssuer and ClaimedSubject are
// available before Verify succeeds so a caller can look up which
// registered client and key to verify against — that is a safe use of
// unverified data, since it only selects what to check against, not what
// to trust. Nothing from Assertion should influence an authorization
// decision until Verify returns a VerifiedAssertion.
type Assertion struct {
	compact jose.Compact
	claims  claims
}

// Parse parses a client assertion without verifying its signature.
func Parse(assertion string) (Assertion, error) {
	compact, err := jose.ParseCompact(assertion)
	if err != nil {
		return Assertion{}, fmt.Errorf("clientassertion: %w", err)
	}
	c, err := parseClaims(compact.Payload)
	if err != nil {
		return Assertion{}, err
	}
	return Assertion{compact: compact, claims: c}, nil
}

// KeyID returns the assertion header's "kid", or "" if absent. Untrusted
// until Verify succeeds; use only to select which key to verify against.
func (a Assertion) KeyID() string { return a.compact.Header.KeyID }

// Algorithm returns the algorithm the assertion header claims to use.
// Untrusted until Verify succeeds — callers must still supply the
// algorithm they expect via VerifyPolicy rather than trusting this
// value, exactly as jose.Compact.Verify requires.
func (a Assertion) Algorithm() fapi.SignatureAlgorithm { return a.compact.Header.Algorithm }

// ClaimedIssuer returns the assertion's unverified "iss" claim, for use
// as a client-lookup key only.
func (a Assertion) ClaimedIssuer() string { return a.claims.Issuer }

// ClaimedSubject returns the assertion's unverified "sub" claim, for use
// as a client-lookup key only.
func (a Assertion) ClaimedSubject() string { return a.claims.Subject }

// VerifyPolicy is the set of checks Verify enforces against an Assertion.
type VerifyPolicy struct {
	// ExpectedClientID is the client the caller is trying to
	// authenticate. Both the assertion's iss and sub claims must equal
	// it exactly.
	ExpectedClientID string

	// ExpectedAudiences is the set of endpoint URLs (or issuer
	// identifiers) the assertion's aud claim may equal — one match is
	// enough. Almost always a single value; a caller that also accepts
	// requests via an RFC 8705 §5 mtls_endpoint_aliases URL passes both
	// that alias and the issuer, since a legitimate client's assertion
	// may target either depending on which endpoint it called.
	ExpectedAudiences []string

	// Algorithm is the algorithm this client is registered to sign
	// assertions with. The assertion header's algorithm must equal it
	// exactly — this is what prevents algorithm-confusion attacks, so
	// it must come from the client's registration, never from the
	// assertion itself.
	Algorithm fapi.SignatureAlgorithm

	// Now is the time to validate exp/nbf against.
	Now time.Time

	// MaxLifetime bounds how far in the future (relative to Now) the
	// assertion's exp claim may be. Required — there is no implicit
	// default.
	MaxLifetime time.Duration

	// MaxClockSkew bounds how far in the future (relative to Now) an nbf
	// claim may be, and extends how long past exp an assertion is still
	// accepted. Zero means no tolerance.
	MaxClockSkew time.Duration

	// Replay, if non-nil, is used to detect assertion replay by jti. A
	// nil Replay skips replay detection; server authentication must
	// always supply one.
	Replay ReplayChecker
}

// VerifiedAssertion is what remains once a client assertion has been
// verified: the authenticated client ID and when the assertion expires.
type VerifiedAssertion struct {
	ClientID  string
	ExpiresAt time.Time
}

// Verify checks a's signature against pub and its claims against policy.
func (a Assertion) Verify(ctx context.Context, pub crypto.PublicKey, policy VerifyPolicy) (VerifiedAssertion, error) {
	if policy.ExpectedClientID == "" {
		return VerifiedAssertion{}, fmt.Errorf("clientassertion: ExpectedClientID is empty")
	}
	if len(policy.ExpectedAudiences) == 0 {
		return VerifiedAssertion{}, fmt.Errorf("clientassertion: ExpectedAudiences is empty")
	}
	if policy.Now.IsZero() {
		return VerifiedAssertion{}, fmt.Errorf("clientassertion: Now is zero")
	}
	if policy.MaxLifetime <= 0 {
		return VerifiedAssertion{}, fmt.Errorf("clientassertion: MaxLifetime must be positive")
	}

	if err := a.compact.Verify(pub, policy.Algorithm); err != nil {
		return VerifiedAssertion{}, fmt.Errorf("clientassertion: %w", err)
	}
	c := a.claims

	if c.Issuer != policy.ExpectedClientID || c.Subject != policy.ExpectedClientID {
		return VerifiedAssertion{}, ErrIssuerSubjectMismatch
	}
	if !slices.Contains(policy.ExpectedAudiences, c.Audience) {
		return VerifiedAssertion{}, ErrAudienceMismatch
	}

	exp := time.Unix(c.ExpiresAt, 0)
	if policy.Now.After(exp.Add(policy.MaxClockSkew)) {
		return VerifiedAssertion{}, ErrExpired
	}
	if exp.Sub(policy.Now) > policy.MaxLifetime {
		return VerifiedAssertion{}, ErrLifetimeExceeded
	}
	if c.NotBefore != 0 {
		nbf := time.Unix(c.NotBefore, 0)
		if policy.Now.Before(nbf.Add(-policy.MaxClockSkew)) {
			return VerifiedAssertion{}, ErrNotYetValid
		}
	}

	if policy.Replay != nil {
		// The TTL must cover the same skew the acceptance check above
		// grants (line 138), or a replay in (exp, exp+skew] would still
		// be accepted but no longer be in the replay store.
		if err := policy.Replay.UseOnce(ctx, c.JTI, exp.Add(policy.MaxClockSkew)); err != nil {
			return VerifiedAssertion{}, fmt.Errorf("clientassertion: replay check: %w", err)
		}
	}

	return VerifiedAssertion{ClientID: c.Subject, ExpiresAt: exp}, nil
}

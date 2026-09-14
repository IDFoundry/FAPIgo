package clientattestation

import (
	"context"
	"fmt"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
)

// PoPTypHeader is the required JOSE "typ" header of a Client
// Attestation PoP JWT (draft-07 §5.2).
const PoPTypHeader = "oauth-client-attestation-pop+jwt"

// ReplayChecker records that a Client Attestation PoP's "jti" has been
// used, failing if it has been seen before. draft-07 recommends replay
// detection for the PoP specifically (§10.6, §12.1) — unlike the Client
// Attestation JWT itself, which is deliberately reusable across
// requests (§10.2), each PoP is meant to be single-use. Mirrors
// clientassertion.ReplayChecker and dpop.ReplayChecker's own shape
// exactly.
type ReplayChecker interface {
	UseOnce(ctx context.Context, jti string, expiresAt time.Time) error
}

// PoP is a parsed, but not yet signature-verified, Client Attestation
// PoP JWT.
type PoP struct {
	compact jose.Compact
	claims  popClaims
}

// ParsePoP parses a Client Attestation PoP JWT without verifying its
// signature.
func ParsePoP(pop string) (PoP, error) {
	compact, err := jose.ParseCompact(pop)
	if err != nil {
		return PoP{}, fmt.Errorf("clientattestation: %w", err)
	}
	c, err := parsePoPClaims(compact.Payload)
	if err != nil {
		return PoP{}, err
	}
	return PoP{compact: compact, claims: c}, nil
}

// Algorithm returns the algorithm the header claims to use.
func (p PoP) Algorithm() fapi.SignatureAlgorithm { return p.compact.Header.Algorithm }

// ClaimedIssuer returns the unverified "iss" claim — the OAuth
// client_id — for use as a lookup value only.
func (p PoP) ClaimedIssuer() string { return p.claims.Issuer }

// PoPVerifyPolicy is the set of checks PoP.Verify enforces.
type PoPVerifyPolicy struct {
	// ExpectedIssuer is the client_id being authenticated — draft-07 §9
	// rule 13: the PoP's iss must equal the accompanying Attestation's
	// own sub.
	ExpectedIssuer string

	// ExpectedAudience is this authorization server's own RFC 8414
	// issuer identifier (draft-07 §5.2, §9 rule 10) — a single value,
	// unlike clientassertion.VerifyPolicy.ExpectedAudiences, since
	// draft-07 grants this JWT no endpoint-URL carve-out the way RFC
	// 7523 grants a client assertion.
	ExpectedAudience string

	// ExpectedChallenge, if non-empty, must equal the PoP's challenge
	// claim (draft-07 §8, §9 rule 8). Leave empty if this server
	// doesn't issue challenges and relies on iat freshness alone (§9
	// rule 9's other option).
	ExpectedChallenge string

	// Now is the time to validate iat/nbf against.
	Now time.Time

	// MaxAge bounds how old (relative to Now) the PoP's iat claim may
	// be — draft-07 §9 rule 9's freshness window. Required.
	MaxAge time.Duration

	// MaxClockSkew bounds how far in the future an iat/nbf claim may
	// be. Zero means no tolerance.
	MaxClockSkew time.Duration

	// Replay, if non-nil, is used to detect PoP replay by jti. A nil
	// Replay skips replay detection; server authentication should
	// always supply one (draft-07 §10.6, §12.1).
	Replay ReplayChecker
}

// VerifiedPoP is what remains once a Client Attestation PoP has been
// verified.
type VerifiedPoP struct {
	ClientID string
	IssuedAt time.Time
}

// Verify checks p's signature against the Client Instance Key found in
// confirmationJWK — VerifiedAttestation.ConfirmationJWK from the
// accompanying, already-verified Client Attestation — and p's claims
// against policy.
//
// The PoP's own header algorithm determines how confirmationJWK is
// interpreted, the same trust model internal/dpop already uses for a
// proof's self-declared "jwk" header: this is safe specifically because
// the key itself is anchored by the separately-verified Client
// Attestation (via Attestation.Verify, checked against an
// Attester public key the caller resolved out of band), not because
// the PoP's header is trusted on its own.
func (p PoP) Verify(ctx context.Context, confirmationJWK []byte, policy PoPVerifyPolicy) (VerifiedPoP, error) {
	if policy.ExpectedIssuer == "" {
		return VerifiedPoP{}, fmt.Errorf("clientattestation: ExpectedIssuer is empty")
	}
	if policy.ExpectedAudience == "" {
		return VerifiedPoP{}, fmt.Errorf("clientattestation: ExpectedAudience is empty")
	}
	if policy.Now.IsZero() {
		return VerifiedPoP{}, fmt.Errorf("clientattestation: Now is zero")
	}
	if policy.MaxAge <= 0 {
		return VerifiedPoP{}, fmt.Errorf("clientattestation: MaxAge must be positive")
	}

	if p.compact.Header.Type != PoPTypHeader {
		return VerifiedPoP{}, fmt.Errorf("%w: got %q, want %q", ErrTypMismatch, p.compact.Header.Type, PoPTypHeader)
	}

	jwk, err := jose.ParseJWK(confirmationJWK, p.compact.Header.Algorithm)
	if err != nil {
		return VerifiedPoP{}, fmt.Errorf("clientattestation: parse confirmation key: %w", err)
	}
	if err := p.compact.Verify(jwk.PublicKey(), p.compact.Header.Algorithm); err != nil {
		return VerifiedPoP{}, fmt.Errorf("clientattestation: %w", err)
	}
	c := p.claims

	if c.Issuer != policy.ExpectedIssuer {
		return VerifiedPoP{}, ErrIssuerMismatch
	}
	if c.Audience != policy.ExpectedAudience {
		return VerifiedPoP{}, ErrAudienceMismatch
	}
	if policy.ExpectedChallenge != "" && c.Challenge != policy.ExpectedChallenge {
		return VerifiedPoP{}, ErrChallengeMismatch
	}

	iat := time.Unix(c.IssuedAt, 0)
	if iat.After(policy.Now.Add(policy.MaxClockSkew)) {
		return VerifiedPoP{}, ErrNotYetValid
	}
	if policy.Now.Sub(iat) > policy.MaxAge {
		return VerifiedPoP{}, ErrExpired
	}
	if c.NotBefore != 0 {
		nbf := time.Unix(c.NotBefore, 0)
		if policy.Now.Before(nbf.Add(-policy.MaxClockSkew)) {
			return VerifiedPoP{}, ErrNotYetValid
		}
	}

	if policy.Replay != nil {
		if err := policy.Replay.UseOnce(ctx, c.JTI, iat.Add(policy.MaxAge)); err != nil {
			return VerifiedPoP{}, fmt.Errorf("clientattestation: replay check: %w", err)
		}
	}

	return VerifiedPoP{ClientID: c.Issuer, IssuedAt: iat}, nil
}

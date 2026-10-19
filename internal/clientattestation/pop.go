package clientattestation

import (
	"context"
	"fmt"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/internal/timeutil"
)

// PoPTypHeader is the required JOSE "typ" header of a Client
// Attestation PoP JWT (draft-12 §5.1).
const PoPTypHeader = "oauth-client-attestation-pop+jwt"

// ReplayChecker records that a Client Attestation PoP's "jti" has been
// used by the Client Instance holding instanceKey, failing if that
// instance has used it before. The draft recommends replay detection
// for the PoP specifically (draft-12 §10.7, §12.1) — unlike the Client
// Attestation JWT itself, which is deliberately reusable across
// requests (§10.2), each PoP is meant to be single-use. The record is
// scoped to the instance, as dpop.ReplayChecker's is to the proof's
// key: every installation of a client shares its client_id, so scoping
// by client alone would let one installation use up a jti another will
// send. A replayed PoP is signed by the same instance key, so it is
// still caught.
type ReplayChecker interface {
	UseOnce(ctx context.Context, instanceKey jose.Thumbprint, jti string, expiresAt time.Time) error
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

// PoPVerifyPolicy is the set of checks PoP.Verify enforces.
type PoPVerifyPolicy struct {
	// ClientID is the client being authenticated: the accompanying
	// Attestation's sub. A PoP's iss claim, if it has one (draft-07
	// required it, §5.2 rule 4; draft-08 removed it), must equal it.
	// Required.
	ClientID string

	// ExpectedAudience is this authorization server's own RFC 8414
	// issuer identifier (draft-12 §5.1, §7.2 rule 7) — a single value,
	// unlike clientassertion.VerifyPolicy.ExpectedAudiences, since the
	// draft grants this JWT no endpoint-URL carve-out the way RFC 7523
	// grants a client assertion. An aud array holding just this value
	// is accepted too; one naming more is not (see popAudience).
	ExpectedAudience string

	// ExpectedChallenge, if non-empty, must equal the PoP's challenge
	// claim (draft-12 §6, §7.2 rule 5). Leave empty if this server
	// doesn't issue challenges and relies on iat freshness alone (§7.2
	// rule 6's other option); a challenge the PoP carries anyway is
	// then ignored.
	ExpectedChallenge string

	// Now is the time to validate iat/exp/nbf against.
	Now time.Time

	// MaxAge bounds how old (relative to Now) the PoP's iat claim may
	// be — draft-12 §7.2 rule 6's freshness window. Required.
	MaxAge time.Duration

	// MaxClockSkew bounds how far in the future an iat/nbf claim may
	// be, and extends how long past an exp claim a PoP is still
	// accepted. Zero means no tolerance.
	MaxClockSkew time.Duration

	// Replay, if non-nil, is used to detect PoP replay by jti. A nil
	// Replay skips replay detection; server authentication should
	// always supply one (draft-12 §10.7, §12.1).
	Replay ReplayChecker
}

// VerifiedPoP is what remains once a Client Attestation PoP has been
// verified.
type VerifiedPoP struct {
	ClientID string
	IssuedAt time.Time
	// InstanceKey is the RFC 7638 thumbprint of the Client Instance Key
	// the PoP verified under: what a refresh token issued to this
	// instance is bound to (draft-12 §10.3).
	InstanceKey jose.Thumbprint
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
	if policy.ClientID == "" {
		return VerifiedPoP{}, fmt.Errorf("clientattestation: ClientID is empty")
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

	if !jose.TypeIs(p.compact.Header.Type, PoPTypHeader) {
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

	if c.Issuer != "" && c.Issuer != policy.ClientID {
		return VerifiedPoP{}, ErrIssuerMismatch
	}
	if string(c.Audience) != policy.ExpectedAudience {
		return VerifiedPoP{}, ErrAudienceMismatch
	}
	if policy.ExpectedChallenge != "" && c.Challenge != policy.ExpectedChallenge {
		return VerifiedPoP{}, ErrChallengeMismatch
	}
	// iat is checked before the replay record (draft-12 §10.7: "MUST
	// first evaluate the iat ... and reject any Client Attestation PoP
	// whose iat falls outside this time window"), so the record's
	// lifetime bounds every PoP it must remember.
	iat := c.IssuedAt.Time()
	if err := checkPoPTimes(c, iat, policy); err != nil {
		return VerifiedPoP{}, err
	}

	instanceKey, err := jwk.Thumbprint()
	if err != nil {
		return VerifiedPoP{}, fmt.Errorf("clientattestation: confirmation key thumbprint: %w", err)
	}
	if policy.Replay != nil {
		// 2×MaxClockSkew past the acceptance window, for an instance
		// whose clock runs behind this one's.
		if err := policy.Replay.UseOnce(ctx, instanceKey, c.JTI, iat.Add(timeutil.SaturatingAdd(policy.MaxAge, policy.MaxClockSkew, policy.MaxClockSkew))); err != nil {
			return VerifiedPoP{}, fmt.Errorf("clientattestation: replay check: %w", err)
		}
	}
	return VerifiedPoP{ClientID: policy.ClientID, IssuedAt: iat, InstanceKey: instanceKey}, nil
}

// checkPoPTimes checks a PoP's iat against the freshness window
// (draft-12 §7.2 rule 6) — no further in the future than MaxClockSkew,
// no older than MaxAge — and, when it has them, its exp (RFC 7519
// §4.1.4, with MaxClockSkew's allowance) and nbf.
func checkPoPTimes(c popClaims, iat time.Time, policy PoPVerifyPolicy) error {
	latest := policy.Now.Add(policy.MaxClockSkew)
	if iat.After(latest) {
		return ErrNotYetValid
	}
	if policy.Now.Sub(iat) > policy.MaxAge {
		return ErrExpired
	}
	if c.ExpiresAt != 0 && policy.Now.After(c.ExpiresAt.Time().Add(policy.MaxClockSkew)) {
		return ErrExpired
	}
	if c.NotBefore != 0 && c.NotBefore.Time().After(latest) {
		return ErrNotYetValid
	}
	return nil
}

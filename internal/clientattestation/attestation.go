package clientattestation

import (
	"crypto"
	"fmt"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
)

// TypHeader is the required JOSE "typ" header of a Client Attestation
// JWT (draft-07 §5.1).
const TypHeader = "oauth-client-attestation+jwt"

// Attestation is a parsed, but not yet signature-verified, Client
// Attestation JWT. KeyID, Algorithm, ClaimedIssuer and ClaimedSubject
// are available before Verify succeeds so a caller can look up which
// Attester and key to verify against — a safe use of unverified data,
// since it only selects what to check against, not what to trust.
// Nothing from Attestation should influence an authentication decision
// until Verify returns a VerifiedAttestation.
type Attestation struct {
	compact jose.Compact
	claims  attestationClaims
}

// Parse parses a Client Attestation JWT without verifying its
// signature.
func Parse(attestation string) (Attestation, error) {
	compact, err := jose.ParseCompact(attestation)
	if err != nil {
		return Attestation{}, fmt.Errorf("clientattestation: %w", err)
	}
	c, err := parseAttestationClaims(compact.Payload)
	if err != nil {
		return Attestation{}, err
	}
	return Attestation{compact: compact, claims: c}, nil
}

// KeyID returns the header's "kid", or "" if absent. Untrusted until
// Verify succeeds; use only to select which Attester key to verify
// against.
func (a Attestation) KeyID() string { return a.compact.Header.KeyID }

// Algorithm returns the algorithm the header claims to use. Untrusted
// until Verify succeeds — callers must still supply the algorithm they
// expect via VerifyPolicy rather than trusting this value, exactly as
// jose.Compact.Verify requires.
func (a Attestation) Algorithm() fapi.SignatureAlgorithm { return a.compact.Header.Algorithm }

// ClaimedIssuer returns the unverified "iss" claim — the Attester — for
// use as a key-lookup value only.
func (a Attestation) ClaimedIssuer() string { return a.claims.Issuer }

// ClaimedSubject returns the unverified "sub" claim — the OAuth
// client_id — for use as a client-lookup key only.
func (a Attestation) ClaimedSubject() string { return a.claims.Subject }

// VerifyPolicy is the set of checks Verify enforces against an
// Attestation.
type VerifyPolicy struct {
	// ExpectedIssuer is the Attester this client is registered to
	// trust (storage.RegisteredClient.ExpectedAttesterIssuer). The
	// attestation's iss claim must equal it exactly.
	ExpectedIssuer string

	// ExpectedSubject is the client_id being authenticated. The
	// attestation's sub claim must equal it exactly.
	ExpectedSubject string

	// Algorithm is the algorithm this client is registered to accept
	// Client Attestations signed with. The header's algorithm must
	// equal it exactly — this is what prevents algorithm-confusion
	// attacks, so it must come from the client's registration, never
	// from the attestation itself.
	Algorithm fapi.SignatureAlgorithm

	// Now is the time to validate exp/nbf against.
	Now time.Time

	// MaxLifetime bounds how far in the future (relative to Now) the
	// attestation's exp claim may be. Required — there is no implicit
	// default.
	MaxLifetime time.Duration

	// MaxClockSkew bounds how far in the future an nbf claim may be,
	// and extends how long past exp an attestation is still accepted.
	// Zero means no tolerance.
	MaxClockSkew time.Duration
}

// VerifiedAttestation is what remains once a Client Attestation has
// been verified.
type VerifiedAttestation struct {
	ClientID  string
	ExpiresAt time.Time

	// ConfirmationJWK is the raw JSON of the attestation's cnf.jwk
	// member — the Client Instance Key the accompanying PoP JWT
	// (PoP.Verify's confirmationJWK parameter) must be verified
	// against. Deliberately left unparsed here: draft-07 doesn't
	// require cnf.jwk to declare its own algorithm, and it's the PoP
	// JWT's own header alg that determines how to interpret it — see
	// pop.go's own doc comment. jose.ParseJWK only ever extracts public
	// key material (there is no private-key field in its parsed
	// shape), which is what satisfies draft-07 §9 rule 6 ("the key
	// contained in the cnf claim... is not a private key") — by
	// construction, not by an explicit check here.
	ConfirmationJWK []byte
}

// Verify checks a's signature against pub and its claims against
// policy.
func (a Attestation) Verify(pub crypto.PublicKey, policy VerifyPolicy) (VerifiedAttestation, error) {
	if policy.ExpectedIssuer == "" {
		return VerifiedAttestation{}, fmt.Errorf("clientattestation: ExpectedIssuer is empty")
	}
	if policy.ExpectedSubject == "" {
		return VerifiedAttestation{}, fmt.Errorf("clientattestation: ExpectedSubject is empty")
	}
	if policy.Now.IsZero() {
		return VerifiedAttestation{}, fmt.Errorf("clientattestation: Now is zero")
	}
	if policy.MaxLifetime <= 0 {
		return VerifiedAttestation{}, fmt.Errorf("clientattestation: MaxLifetime must be positive")
	}

	if a.compact.Header.Type != TypHeader {
		return VerifiedAttestation{}, fmt.Errorf("%w: got %q, want %q", ErrTypMismatch, a.compact.Header.Type, TypHeader)
	}
	if err := a.compact.Verify(pub, policy.Algorithm); err != nil {
		return VerifiedAttestation{}, fmt.Errorf("clientattestation: %w", err)
	}
	c := a.claims

	if c.Issuer != policy.ExpectedIssuer {
		return VerifiedAttestation{}, ErrIssuerMismatch
	}
	if c.Subject != policy.ExpectedSubject {
		return VerifiedAttestation{}, ErrSubjectMismatch
	}

	exp := time.Unix(c.ExpiresAt, 0)
	if policy.Now.After(exp.Add(policy.MaxClockSkew)) {
		return VerifiedAttestation{}, ErrExpired
	}
	if exp.Sub(policy.Now) > policy.MaxLifetime {
		return VerifiedAttestation{}, ErrLifetimeExceeded
	}
	if c.NotBefore != 0 {
		nbf := time.Unix(c.NotBefore, 0)
		if policy.Now.Before(nbf.Add(-policy.MaxClockSkew)) {
			return VerifiedAttestation{}, ErrNotYetValid
		}
	}

	return VerifiedAttestation{
		ClientID:        c.Subject,
		ExpiresAt:       exp,
		ConfirmationJWK: []byte(c.Confirmation.JWK),
	}, nil
}

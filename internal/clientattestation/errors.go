package clientattestation

import "errors"

var (
	// ErrMalformedClaims indicates a JWT's claims payload was missing a
	// required claim, had an aud claim (PoP) that was not a single
	// string, or otherwise didn't parse into this package's expected
	// shape.
	ErrMalformedClaims = errors.New("clientattestation: malformed claims")

	// ErrTypMismatch indicates a JWT's "typ" header did not equal
	// TypHeader (Attestation) or PoPTypHeader (PoP).
	ErrTypMismatch = errors.New("clientattestation: typ header mismatch")

	// ErrIssuerMismatch indicates a JWT's iss claim did not equal the
	// caller's expected value (the trusted Attester for an Attestation;
	// the client_id for a PoP).
	ErrIssuerMismatch = errors.New("clientattestation: iss does not match expected value")

	// ErrSubjectMismatch indicates a Client Attestation's sub claim did
	// not equal the client_id the caller expected to authenticate.
	ErrSubjectMismatch = errors.New("clientattestation: sub does not match expected client ID")

	// ErrAudienceMismatch indicates a PoP's aud claim did not equal the
	// caller's expected audience (this server's own issuer identifier).
	ErrAudienceMismatch = errors.New("clientattestation: aud does not match expected audience")

	// ErrChallengeMismatch indicates a PoP's challenge claim did not
	// equal the challenge the caller previously issued.
	ErrChallengeMismatch = errors.New("clientattestation: challenge does not match expected value")

	// ErrExpired indicates an Attestation's exp claim, or a PoP's iat
	// claim, is outside the acceptable window as of the verification
	// time.
	ErrExpired = errors.New("clientattestation: expired")

	// ErrNotYetValid indicates a nbf claim (or, for a PoP, iat) is in
	// the future beyond the configured clock-skew tolerance.
	ErrNotYetValid = errors.New("clientattestation: not yet valid")

	// ErrLifetimeExceeded indicates an Attestation's exp claim is
	// further in the future than the configured maximum lifetime
	// allows.
	ErrLifetimeExceeded = errors.New("clientattestation: exp exceeds maximum allowed lifetime")
)

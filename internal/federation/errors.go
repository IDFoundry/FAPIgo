package federation

import "errors"

var (
	// ErrWrongType indicates the statement's JWS "typ" header was not
	// "entity-statement+jwt" — unlike internal/requestobject's own
	// "typ", OpenID Federation 1.0 §3.1/§3.2 requires this header
	// unconditionally ("The Entity Statement MUST be explicitly
	// typed"), so — unlike a request object — a missing "typ" is
	// rejected too, not merely a present-and-wrong one.
	ErrWrongType = errors.New("federation: header typ is not entity-statement+jwt")

	// ErrMalformedClaims indicates the payload was not a JSON object, or
	// was missing a required top-level claim (iss, sub, iat, exp, jwks).
	ErrMalformedClaims = errors.New("federation: malformed claims")

	// ErrMalformedJWKS indicates the "jwks" claim was present but not a
	// well-formed JWK Set.
	ErrMalformedJWKS = errors.New("federation: malformed jwks claim")

	// ErrSubjectMismatch indicates a parsed statement's "sub" claim did
	// not equal the entity identifier the caller expected it to be
	// about.
	ErrSubjectMismatch = errors.New("federation: sub does not match expected subject")

	// ErrIssuerMismatch indicates a parsed statement's "iss" claim did
	// not equal the entity identifier the caller expected to have
	// issued it.
	ErrIssuerMismatch = errors.New("federation: iss does not match expected issuer")

	// ErrExpired indicates the statement's exp claim is not after the
	// verification time.
	ErrExpired = errors.New("federation: statement has expired")

	// ErrNotYetValid indicates the statement's iat claim is in the
	// future beyond the configured clock-skew tolerance.
	ErrNotYetValid = errors.New("federation: statement is not yet valid")

	// ErrLifetimeExceeded indicates the statement's exp claim is further
	// in the future than the configured maximum lifetime allows.
	ErrLifetimeExceeded = errors.New("federation: exp exceeds maximum allowed lifetime")

	// ErrNoMatchingKey indicates none of the issuer's candidate keys
	// (resolved by the statement header's "kid" from the issuer's own
	// published jwks) could be matched before verification was
	// attempted.
	ErrNoMatchingKey = errors.New("federation: no issuer key matches the statement's kid")

	// ErrTrustMarkWrongType indicates a Trust Mark JWT's "typ" header
	// was not "trust-mark+jwt" (OpenID Federation 1.0 §7's own "Trust
	// Marks without a typ header parameter or an unrecognized typ value
	// MUST be rejected").
	ErrTrustMarkWrongType = errors.New("federation: trust mark header typ is not trust-mark+jwt")

	// ErrTrustMarkTypeMismatch indicates a Trust Mark's own
	// "trust_mark_type" claim did not equal the type its wrapper
	// RawTrustMark declared it under.
	ErrTrustMarkTypeMismatch = errors.New("federation: trust mark's own trust_mark_type does not match its declared type")

	// ErrTrustMarkExpired indicates the Trust Mark's exp claim (when
	// present at all — an absent exp means it never expires) is not
	// after the verification time.
	ErrTrustMarkExpired = errors.New("federation: trust mark has expired")

	// ErrTrustMarkNotYetValid indicates the Trust Mark's iat claim is in
	// the future beyond the configured clock-skew tolerance.
	ErrTrustMarkNotYetValid = errors.New("federation: trust mark is not yet valid")

	// ErrTrustMarkDelegationWrongType indicates a Trust Mark Delegation
	// JWT's "typ" header was not "trust-mark-delegation+jwt" (OpenID
	// Federation 1.0 §7.2's own "Trust Mark delegation JWTs without a
	// typ header parameter or with a different typ value MUST be
	// rejected").
	ErrTrustMarkDelegationWrongType = errors.New("federation: trust mark delegation header typ is not trust-mark-delegation+jwt")

	// ErrTrustMarkDelegationTypeMismatch indicates a delegation's own
	// "trust_mark_type" claim did not equal the Trust Mark's own.
	ErrTrustMarkDelegationTypeMismatch = errors.New("federation: trust mark delegation's own trust_mark_type does not match the trust mark's")

	// ErrTrustMarkDelegationExpired indicates the delegation's exp claim
	// (when present at all — an absent exp means it never expires) is
	// not after the verification time.
	ErrTrustMarkDelegationExpired = errors.New("federation: trust mark delegation has expired")

	// ErrTrustMarkDelegationNotYetValid indicates the delegation's iat
	// claim is in the future beyond the configured clock-skew tolerance.
	ErrTrustMarkDelegationNotYetValid = errors.New("federation: trust mark delegation is not yet valid")
)

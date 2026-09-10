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
)

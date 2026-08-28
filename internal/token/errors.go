package token

import "errors"

var (
	// ErrWrongType indicates an access token header's "typ" was not
	// "at+jwt" (RFC 9068 §2.1).
	ErrWrongType = errors.New("token: header typ is not at+jwt")

	// ErrMalformedClaims indicates a payload was not a JSON object, was
	// missing a required top-level claim, or had a claim of the wrong
	// shape (including a "cnf" claim that was not a well-formed
	// DPoP-thumbprint confirmation).
	ErrMalformedClaims = errors.New("token: malformed claims")

	// ErrIssuerMismatch indicates a token's iss claim did not equal the
	// issuer the caller expected.
	ErrIssuerMismatch = errors.New("token: iss does not match expected issuer")

	// ErrAudienceMismatch indicates a token's aud claim did not contain
	// the audience the caller expected, or — for an ID token — named an
	// additional audience the caller's IDTokenValidatePolicy.
	// TrustedAudiences doesn't list (OIDC Core §3.1.3.7 step 3).
	ErrAudienceMismatch = errors.New("token: aud does not match expected audience")

	// ErrExpired indicates a token's exp claim is not after the
	// verification time.
	ErrExpired = errors.New("token: token has expired")

	// ErrLifetimeExceeded indicates a token's exp claim is further in
	// the future than the configured maximum lifetime allows.
	ErrLifetimeExceeded = errors.New("token: exp exceeds maximum allowed lifetime")

	// ErrNonceMismatch indicates an ID token's nonce claim did not match
	// the nonce the caller's authorization request carried.
	ErrNonceMismatch = errors.New("token: nonce does not match expected value")

	// ErrMissingAuthorizedParty indicates an ID token's aud claim named
	// more than one audience but carried no azp claim (OIDC Core
	// §3.1.3.7 step 9) — needed to disambiguate which of those
	// audiences the token was actually authorized for.
	ErrMissingAuthorizedParty = errors.New("token: aud has multiple audiences but azp is missing")

	// ErrAuthorizedPartyMismatch indicates an ID token's azp claim did
	// not equal the caller's own client ID (OIDC Core §3.1.3.7 step 10).
	ErrAuthorizedPartyMismatch = errors.New("token: azp does not match expected audience")

	// ErrIssuedAtTooOld indicates an ID token's iat claim is further in
	// the past than the configured maximum lifetime allows — OIDC Core
	// §3.1.3.7 step 10: "iat... can be used to reject tokens that were
	// issued too far away from the current time." Mirrors
	// ErrLifetimeExceeded's own bound on exp, applied to the opposite
	// direction around Now.
	ErrIssuedAtTooOld = errors.New("token: iat exceeds maximum allowed age")
)

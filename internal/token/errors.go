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

	// ErrAudienceMismatch indicates a token's aud claim did not equal
	// the audience the caller expected — for an ID token, whose aud may
	// per OIDC Core §2 be an array, every element must equal it, not
	// merely one of them (OIDC Core §3.1.3.7 step 3 requires rejecting
	// any additional audience this package has no mechanism to trust).
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

	// ErrMissingConfirmation indicates the caller required a
	// sender-constrained access token (via ExpectedThumbprint) but the
	// token carried no cnf.jkt claim at all.
	ErrMissingConfirmation = errors.New("token: access token has no cnf.jkt confirmation")

	// ErrConfirmationMismatch indicates an access token's cnf.jkt did
	// not match the DPoP key thumbprint the caller expected.
	ErrConfirmationMismatch = errors.New("token: cnf.jkt does not match expected key thumbprint")
)

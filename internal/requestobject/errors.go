package requestobject

import "errors"

var (
	// ErrWrongType indicates the object's "typ" header was not
	// "oauth-authz-req+jwt" (RFC 9101 §10.8).
	ErrWrongType = errors.New("requestobject: header typ is not oauth-authz-req+jwt")

	// ErrMalformedClaims indicates the payload was not a JSON object, or
	// was missing a required top-level claim (iss, aud or exp).
	ErrMalformedClaims = errors.New("requestobject: malformed claims")

	// ErrClientIDIssuerMismatch indicates the payload's "client_id"
	// parameter (RFC 9101 §5.3) did not equal its "iss" claim.
	ErrClientIDIssuerMismatch = errors.New("requestobject: client_id parameter does not match iss")

	// ErrIssuerMismatch indicates the object's iss claim did not equal
	// the client ID the caller expected to authenticate.
	ErrIssuerMismatch = errors.New("requestobject: iss does not match expected client ID")

	// ErrAudienceMismatch indicates the object's aud claim did not equal
	// the audience (authorization server issuer identifier) the caller
	// expected.
	ErrAudienceMismatch = errors.New("requestobject: aud does not match expected audience")

	// ErrExpired indicates the object's exp claim is not after the
	// verification time.
	ErrExpired = errors.New("requestobject: object has expired")

	// ErrNotYetValid indicates the object's nbf claim is in the future
	// beyond the configured clock-skew tolerance.
	ErrNotYetValid = errors.New("requestobject: object is not yet valid")

	// ErrLifetimeExceeded indicates the object's exp claim is further in
	// the future than the configured maximum lifetime allows.
	ErrLifetimeExceeded = errors.New("requestobject: exp exceeds maximum allowed lifetime")

	// ErrMissingJTI indicates replay detection was requested but the
	// object carries no jti claim to key it by.
	ErrMissingJTI = errors.New("requestobject: replay detection requires a jti claim")
)

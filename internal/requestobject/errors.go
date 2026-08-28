package requestobject

import "errors"

var (
	// ErrWrongType indicates the object's "typ" header was present but
	// did not identify a request object (RFC 9101 §10.8) even after the
	// case-insensitive, "application/"-prefix-tolerant comparison
	// isRequestObjectType applies. An absent "typ" header is not an
	// error — see jwtType's doc comment.
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

	// ErrAudienceMismatch indicates the object's aud claim (a single
	// value or, per RFC 7519 §4.1.3, an array of values) did not contain
	// the audience (authorization server issuer identifier) the caller
	// expected.
	ErrAudienceMismatch = errors.New("requestobject: aud does not match expected audience")

	// ErrExpired indicates the object's exp claim is not after the
	// verification time.
	ErrExpired = errors.New("requestobject: object has expired")

	// ErrNotYetValid indicates the object's nbf claim is in the future
	// beyond the configured clock-skew tolerance.
	ErrNotYetValid = errors.New("requestobject: object is not yet valid")

	// ErrMissingNotBefore indicates VerifyPolicy.RequireNotBefore was set
	// but the object carries no nbf claim at all.
	ErrMissingNotBefore = errors.New("requestobject: nbf claim is required")

	// ErrMissingIssuedAt indicates VerifyPolicy.RequireIssuedAt was set
	// but the object carries no iat claim at all.
	ErrMissingIssuedAt = errors.New("requestobject: iat claim is required")

	// ErrMissingJTI indicates VerifyPolicy.RequireJTI was set but the
	// object carries no jti claim at all.
	ErrMissingJTI = errors.New("requestobject: jti claim is required")

	// ErrLifetimeExceeded indicates the object's exp claim is further in
	// the future than the configured maximum lifetime allows.
	ErrLifetimeExceeded = errors.New("requestobject: exp exceeds maximum allowed lifetime")

	// ErrNotBeforeTooOld indicates the object's nbf claim is further in
	// the past than the configured maximum lifetime allows. Symmetric
	// with ErrLifetimeExceeded: that bounds how far exp may sit in the
	// future of Now, this bounds how far nbf may sit in the past of
	// Now — without it, an object with a normal, unexpired exp but an
	// ancient nbf would sail through both other checks despite claiming
	// an unreasonably long validity window, which is exactly what FAPI
	// 2.0 Message Signing Final §5.3.1 (FAPI2-MS-ID1-5.3.1-3) requires
	// be rejected.
	ErrNotBeforeTooOld = errors.New("requestobject: nbf exceeds maximum allowed age")
)

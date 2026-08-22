package jarm

import "errors"

var (
	// ErrMalformedClaims indicates the response payload was not a JSON
	// object, or was missing a required top-level claim (iss, aud or
	// exp).
	ErrMalformedClaims = errors.New("jarm: malformed claims")

	// ErrIssuerMismatch indicates the response's iss claim did not equal
	// the authorization server the caller expected the response to come
	// from.
	ErrIssuerMismatch = errors.New("jarm: iss does not match expected issuer")

	// ErrAudienceMismatch indicates the response's aud claim did not
	// equal the caller's own client ID.
	ErrAudienceMismatch = errors.New("jarm: aud does not match expected audience")

	// ErrExpired indicates the response's exp claim is not after the
	// verification time.
	ErrExpired = errors.New("jarm: response has expired")

	// ErrNotYetValid indicates the response's nbf claim is in the future
	// beyond the configured clock-skew tolerance.
	ErrNotYetValid = errors.New("jarm: response is not yet valid")

	// ErrLifetimeExceeded indicates the response's exp claim is further
	// in the future than the configured maximum lifetime allows.
	ErrLifetimeExceeded = errors.New("jarm: exp exceeds maximum allowed lifetime")

	// ErrNotAuthorizationResponse indicates a token that otherwise
	// verifies (signature, iss, aud, exp/nbf all check out) carries
	// neither a "code" nor an "error" parameter — so it isn't an
	// authorization response at all, even though it may be a validly
	// signed JWT from the same issuer for the same audience, such as an
	// ID token. The OpenID JARM spec defines no mandatory "typ" for the
	// response JWT, so this checks for the substance of an authorization
	// response instead of relying on a media type third-party
	// authorization servers aren't required to set.
	ErrNotAuthorizationResponse = errors.New("jarm: response carries neither a code nor an error parameter")
)

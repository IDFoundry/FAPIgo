package dpop

import "errors"

var (
	// ErrWrongType indicates the proof's "typ" header was not "dpop+jwt".
	ErrWrongType = errors.New("dpop: header typ is not dpop+jwt")

	// ErrMissingJWK indicates the proof's header had no embedded "jwk".
	ErrMissingJWK = errors.New("dpop: header is missing jwk")

	// ErrMethodMismatch indicates the proof's "htm" claim did not match
	// the HTTP method of the request it was presented with.
	ErrMethodMismatch = errors.New("dpop: htm does not match request method")

	// ErrURIMismatch indicates the proof's "htu" claim did not match the
	// canonicalized target URI of the request it was presented with.
	ErrURIMismatch = errors.New("dpop: htu does not match request URI")

	// ErrURLNotNormal indicates CreateProof was asked for a proof for a
	// URL whose path has dot segments or percent-encoded unreserved
	// characters (see canonical.HasNormalPath): its htu would name
	// another path than the one the request is sent to.
	ErrURLNotNormal = errors.New("dpop: url path has dot segments or percent-encoded unreserved characters")

	// ErrIssuedInFuture indicates the proof's "iat" claim is further in
	// the future than the configured clock-skew tolerance allows.
	ErrIssuedInFuture = errors.New("dpop: iat is in the future")

	// ErrNotYetValid indicates the proof's "nbf" claim is further in the
	// future than the allowed clock skew (RFC 7519 §4.1.5; FAPI 2.0
	// Security Profile §5.3.2.1 item 13).
	ErrNotYetValid = errors.New("dpop: nbf is in the future")

	// ErrExpired indicates the proof's "iat" claim is older than the
	// configured maximum proof age.
	ErrExpired = errors.New("dpop: proof has expired")

	// ErrAccessTokenHashMismatch indicates the proof's "ath" claim did
	// not match the presented access token, or was present/absent when
	// the opposite was expected.
	ErrAccessTokenHashMismatch = errors.New("dpop: ath does not match access token")

	// ErrNonceMismatch indicates the proof's "nonce" claim did not match
	// the nonce the verifier requires.
	ErrNonceMismatch = errors.New("dpop: nonce does not match required value")

	// ErrMalformedClaims indicates the proof payload was missing a
	// required claim (jti, htm or htu) or contained an unrecognized one.
	ErrMalformedClaims = errors.New("dpop: malformed claims")
)

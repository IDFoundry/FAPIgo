package clientassertion

import "errors"

var (
	// ErrMalformedClaims indicates the assertion payload was missing a
	// required claim (iss, sub, aud, jti or exp), had an aud claim that
	// was not a single string, or contained a claim this package does
	// not recognize.
	ErrMalformedClaims = errors.New("clientassertion: malformed claims")

	// ErrIssuerSubjectMismatch indicates the assertion's iss and/or sub
	// claim did not equal the client ID the caller expected to
	// authenticate.
	ErrIssuerSubjectMismatch = errors.New("clientassertion: iss/sub does not match expected client ID")

	// ErrAudienceMismatch indicates the assertion's aud claim did not
	// equal the audience the caller expected (typically its own token
	// or PAR endpoint URL).
	ErrAudienceMismatch = errors.New("clientassertion: aud does not match expected audience")

	// ErrExpired indicates the assertion's exp claim is not after the
	// verification time.
	ErrExpired = errors.New("clientassertion: assertion has expired")

	// ErrNotYetValid indicates the assertion's nbf claim is in the
	// future beyond the configured clock-skew tolerance.
	ErrNotYetValid = errors.New("clientassertion: assertion is not yet valid")

	// ErrLifetimeExceeded indicates the assertion's exp claim is further
	// in the future than the configured maximum lifetime allows.
	ErrLifetimeExceeded = errors.New("clientassertion: exp exceeds maximum allowed lifetime")
)

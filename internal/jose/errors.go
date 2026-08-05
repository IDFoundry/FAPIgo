package jose

import "errors"

var (
	// ErrMalformed indicates a compact serialization that is not
	// well-formed (wrong number of segments, empty segment, invalid
	// base64url).
	ErrMalformed = errors.New("jose: malformed compact serialization")

	// ErrTooLarge indicates a compact serialization larger than this
	// package is willing to parse.
	ErrTooLarge = errors.New("jose: compact serialization exceeds maximum size")

	// ErrAlgorithmMismatch indicates the algorithm recorded in a JWS
	// header does not match the algorithm the caller required.
	ErrAlgorithmMismatch = errors.New("jose: algorithm mismatch")

	// ErrInvalidSignature indicates a JWS signature that does not
	// verify against the supplied key.
	ErrInvalidSignature = errors.New("jose: invalid signature")

	// ErrPrivateKeyMaterial indicates a JWK contained a private-key
	// component (e.g. "d", "k") where only a public key is acceptable.
	ErrPrivateKeyMaterial = errors.New("jose: jwk contains private key material")

	// ErrCertificateChain indicates a JWK contained an x5c/x5u/x5t
	// member. This module never trusts a certificate chain embedded in
	// a caller-supplied JWK.
	ErrCertificateChain = errors.New("jose: jwk certificate chain not permitted")
)

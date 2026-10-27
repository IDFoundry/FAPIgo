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

	// ErrRSAKeyTooLarge indicates an RSA JWK whose modulus is longer
	// than this package accepts for where the key came from — see
	// maxCallerRSAModulusBits. It is reported while the key is parsed,
	// before any RSA operation uses it.
	ErrRSAKeyTooLarge = errors.New("jose: rsa key too large")

	// ErrUnsupportedRSAExponent indicates an RSA JWK whose public
	// exponent is not 65537 — see decodeExponent.
	ErrUnsupportedRSAExponent = errors.New("jose: unsupported rsa public exponent")
)

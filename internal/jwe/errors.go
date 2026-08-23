package jwe

import "errors"

var (
	// ErrMalformed indicates a compact serialization that is not
	// well-formed (wrong number of segments, empty segment, invalid
	// base64url).
	ErrMalformed = errors.New("jwe: malformed compact serialization")

	// ErrAlgorithmMismatch indicates the "alg" or "enc" recorded in a
	// JWE header does not match what the caller required.
	ErrAlgorithmMismatch = errors.New("jwe: algorithm mismatch")

	// ErrDecryptionFailed indicates key unwrapping or content decryption
	// failed — a wrong key, a tampered ciphertext/tag, or (for
	// ECDH-ES+A256KW) a key-unwrap integrity check failure. Deliberately
	// undifferentiated: which specific step failed is not safe to expose
	// to a caller processing untrusted input.
	ErrDecryptionFailed = errors.New("jwe: decryption failed")
)

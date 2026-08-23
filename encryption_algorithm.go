package fapi

import "fmt"

// KeyManagementAlgorithm is a closed set of JWE key-management
// algorithms this module supports — how the content-encryption key
// (CEK) for one encrypted token is delivered to its recipient (RFC 7518
// §4). As with SignatureAlgorithm, a JOSE "alg" header is untrusted
// input: a caller states which KeyManagementAlgorithm it expects before
// a JWE is processed, rather than trusting whatever the header claims.
type KeyManagementAlgorithm uint8

const (
	_ KeyManagementAlgorithm = iota

	// ECDHESA256KW is ECDH-ES using Concat KDF, with the agreed key
	// used to wrap the CEK with AES-256 Key Wrap (RFC 7518 §4.6-4.7).
	ECDHESA256KW
)

// String returns the JOSE "alg" header value for a, or "" if a is not a
// recognized algorithm.
func (a KeyManagementAlgorithm) String() string {
	switch a {
	case ECDHESA256KW:
		return "ECDH-ES+A256KW"
	default:
		return ""
	}
}

// IsValid reports whether a is one of the algorithms this module
// supports.
func (a KeyManagementAlgorithm) IsValid() bool {
	switch a {
	case ECDHESA256KW:
		return true
	default:
		return false
	}
}

// ParseKeyManagementAlgorithm maps a JOSE "alg" header value to a
// KeyManagementAlgorithm. It rejects every value outside the closed set
// this module supports, including algorithms that are valid JOSE
// algorithms in general (e.g. "RSA-OAEP-256", "dir"), for the same
// reason ParseSignatureAlgorithm does: accepting one outside this
// module's own closed set would silently downgrade the guarantees the
// rest of this module assumes.
func ParseKeyManagementAlgorithm(alg string) (KeyManagementAlgorithm, error) {
	switch alg {
	case "ECDH-ES+A256KW":
		return ECDHESA256KW, nil
	default:
		return 0, fmt.Errorf("fapi: unsupported key management algorithm %q", alg)
	}
}

// ContentEncryptionAlgorithm is a closed set of JWE content-encryption
// algorithms this module supports — how the payload itself is encrypted
// once a CEK has been established (RFC 7518 §5).
type ContentEncryptionAlgorithm uint8

const (
	_ ContentEncryptionAlgorithm = iota

	// A256GCM is AES-256 in Galois/Counter Mode (RFC 7518 §5.3), an AEAD
	// cipher — no separate integrity algorithm is layered on top the way
	// the CBC-HMAC family requires.
	A256GCM
)

// String returns the JOSE "enc" header value for a, or "" if a is not a
// recognized algorithm.
func (a ContentEncryptionAlgorithm) String() string {
	switch a {
	case A256GCM:
		return "A256GCM"
	default:
		return ""
	}
}

// IsValid reports whether a is one of the algorithms this module
// supports.
func (a ContentEncryptionAlgorithm) IsValid() bool {
	switch a {
	case A256GCM:
		return true
	default:
		return false
	}
}

// ParseContentEncryptionAlgorithm maps a JOSE "enc" header value to a
// ContentEncryptionAlgorithm. It rejects every value outside the closed
// set this module supports, for the same reason
// ParseKeyManagementAlgorithm does.
func ParseContentEncryptionAlgorithm(enc string) (ContentEncryptionAlgorithm, error) {
	switch enc {
	case "A256GCM":
		return A256GCM, nil
	default:
		return 0, fmt.Errorf("fapi: unsupported content encryption algorithm %q", enc)
	}
}

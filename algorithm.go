package fapi

import "fmt"

// SignatureAlgorithm is a closed set of JWS signature algorithms this
// module supports. It exists so a JWT/JWS "alg" header — untrusted
// input — is never treated as policy: callers state which
// SignatureAlgorithm they expect before a signature is checked, rather
// than trusting whatever the token header claims.
type SignatureAlgorithm uint8

const (
	_ SignatureAlgorithm = iota

	// ES256 is ECDSA using the P-256 curve and SHA-256 (RFC 7518 §3.4).
	ES256

	// PS256 is RSASSA-PSS using SHA-256 and MGF1 with SHA-256
	// (RFC 7518 §3.5), with a minimum 2048-bit modulus.
	PS256
)

// String returns the JOSE "alg" header value for a, or "" if a is not a
// recognized algorithm.
func (a SignatureAlgorithm) String() string {
	switch a {
	case ES256:
		return "ES256"
	case PS256:
		return "PS256"
	default:
		return ""
	}
}

// IsValid reports whether a is one of the algorithms this module
// supports.
func (a SignatureAlgorithm) IsValid() bool {
	switch a {
	case ES256, PS256:
		return true
	default:
		return false
	}
}

// ParseSignatureAlgorithm maps a JOSE "alg" header value to a
// SignatureAlgorithm. It rejects every value outside the closed set this
// module supports, including algorithms that are valid JOSE algorithms
// in general — "none", "HS256", "RS256" and so on — since accepting one
// of those would silently downgrade the sender-constraint and
// integrity guarantees the rest of this module assumes.
func ParseSignatureAlgorithm(alg string) (SignatureAlgorithm, error) {
	switch alg {
	case "ES256":
		return ES256, nil
	case "PS256":
		return PS256, nil
	default:
		return 0, fmt.Errorf("fapi: unsupported signature algorithm %q", alg)
	}
}

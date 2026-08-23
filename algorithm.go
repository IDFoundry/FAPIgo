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

	// EdDSA is pure EdDSA using the Ed25519 variant (RFC 8037 §3.1) —
	// the third algorithm FAPI 2.0 Security Profile Final §5.4.1 item
	// 1.b permits, alongside ES256 and PS256. Unlike those two, EdDSA
	// signs the JWS Signing Input directly rather than a digest of it
	// (RFC 8037 §3.1: "the JWS Signing Input (as message)") — this
	// module's own SignatureAlgorithm doesn't encode that difference
	// itself, but every caller that produces or checks a signature
	// (internal/jose, keys.KeyManager) must not pre-hash for this
	// algorithm the way it does for ES256/PS256.
	EdDSA
)

// String returns the JOSE "alg" header value for a, or "" if a is not a
// recognized algorithm.
func (a SignatureAlgorithm) String() string {
	switch a {
	case ES256:
		return "ES256"
	case PS256:
		return "PS256"
	case EdDSA:
		return "EdDSA"
	default:
		return ""
	}
}

// IsValid reports whether a is one of the algorithms this module
// supports.
func (a SignatureAlgorithm) IsValid() bool {
	switch a {
	case ES256, PS256, EdDSA:
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
	case "EdDSA":
		return EdDSA, nil
	default:
		return 0, fmt.Errorf("fapi: unsupported signature algorithm %q", alg)
	}
}

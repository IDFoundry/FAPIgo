package jose

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	fapi "github.com/idfoundry/fapigo"
)

// maxCompactBytes bounds how large a compact serialization this package
// will attempt to parse, to avoid doing unbounded work on attacker-
// supplied input before any signature has been checked.
const maxCompactBytes = 16 * 1024

// Sign produces a JWS compact serialization:
// BASE64URL(header) || "." || BASE64URL(payload) || "." || BASE64URL(signature).
//
// If header.JWK is set, it must match signer's public key — Sign refuses
// to produce a proof that asserts possession of a key other than the one
// actually used to sign.
func Sign(signer crypto.Signer, header Header, payload []byte) (string, error) {
	if signer == nil {
		return "", fmt.Errorf("jose: signer is nil")
	}
	if !header.Algorithm.IsValid() {
		return "", fmt.Errorf("jose: invalid algorithm %v", header.Algorithm)
	}
	if header.JWK != nil {
		eq, ok := signer.Public().(interface{ Equal(crypto.PublicKey) bool })
		if !ok || !eq.Equal(header.JWK.PublicKey()) {
			return "", fmt.Errorf("jose: header jwk does not match signer's public key")
		}
	}

	headerJSON, err := marshalHeader(header)
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(payload)

	var sig []byte
	switch header.Algorithm {
	case fapi.ES256:
		hash := sha256.Sum256([]byte(signingInput))
		sig, err = signECDSA(signer, hash[:])
	case fapi.PS256:
		hash := sha256.Sum256([]byte(signingInput))
		sig, err = signRSAPSS(signer, hash[:])
	case fapi.EdDSA:
		// No pre-hashing: RFC 8037 §3.1 requires pure EdDSA over the
		// signing input itself, unlike ES256/PS256's digest-then-sign.
		sig, err = signEdDSA(signer, []byte(signingInput))
	default:
		return "", fmt.Errorf("jose: unsupported algorithm %v", header.Algorithm)
	}
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// Compact is a parsed, but not yet signature-verified, JWS compact
// serialization. Header and Payload must not be trusted until Verify
// returns nil.
type Compact struct {
	Header  Header
	Payload []byte

	signingInput []byte
	signature    []byte
}

// ParseCompact splits and decodes a compact JWS without verifying its
// signature.
func ParseCompact(s string) (Compact, error) {
	if len(s) > maxCompactBytes {
		return Compact{}, ErrTooLarge
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return Compact{}, ErrMalformed
	}
	headerB64, payloadB64, sigB64 := parts[0], parts[1], parts[2]
	if headerB64 == "" || payloadB64 == "" || sigB64 == "" {
		return Compact{}, ErrMalformed
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		return Compact{}, fmt.Errorf("%w: header: %v", ErrMalformed, err)
	}
	header, err := parseHeader(headerJSON)
	if err != nil {
		return Compact{}, err
	}
	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return Compact{}, fmt.Errorf("%w: payload: %v", ErrMalformed, err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return Compact{}, fmt.Errorf("%w: signature: %v", ErrMalformed, err)
	}

	return Compact{
		Header:       header,
		Payload:      payload,
		signingInput: []byte(headerB64 + "." + payloadB64),
		signature:    sig,
	}, nil
}

// Verify checks c's signature against pub for exactly alg. It fails if
// the header's own algorithm does not match alg, so a caller must state
// which algorithm it expects rather than trusting whatever the header
// claims — this is what prevents algorithm-confusion attacks.
func (c Compact) Verify(pub crypto.PublicKey, alg fapi.SignatureAlgorithm) error {
	if c.Header.Algorithm != alg {
		return fmt.Errorf("%w: header has %s, expected %s", ErrAlgorithmMismatch, c.Header.Algorithm, alg)
	}
	switch alg {
	case fapi.ES256:
		hash := sha256.Sum256(c.signingInput)
		return verifyECDSA(pub, hash[:], c.signature)
	case fapi.PS256:
		hash := sha256.Sum256(c.signingInput)
		return verifyRSAPSS(pub, hash[:], c.signature)
	case fapi.EdDSA:
		return verifyEdDSA(pub, c.signingInput, c.signature)
	default:
		return fmt.Errorf("jose: unsupported algorithm %v", alg)
	}
}

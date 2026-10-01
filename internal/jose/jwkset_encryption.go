package jose

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/strictjson"
)

// ParsedEncryptionJWK is one encryption key from a parsed JWK Set: what
// a JWE is encrypted to (RFC 7516), as opposed to ParsedJWK's signature
// verification keys.
type ParsedEncryptionJWK struct {
	KeyID     string
	Algorithm fapi.KeyManagementAlgorithm
	// PublicKey is an *rsa.PublicKey for RSAOAEP256 and an
	// *ecdh.PublicKey for ECDHESA256KW.
	PublicKey crypto.PublicKey
}

// ParseEncryptionJWKSet parses a JWK Set's encryption keys into this
// module's closed key management algorithm set. An entry counts as an
// encryption key when its "alg" is a supported key management
// algorithm, or when it has no "alg" but "use":"enc" (RFC 7517 §4.2),
// in which case its key type decides: RSA keys are RSAOAEP256, P-256
// keys ECDHESA256KW. An entry with "use":"sig", a signature "alg", no
// "alg" and no "use", or key material that doesn't fit its algorithm is
// skipped, as ParseJWKSet skips entries it can't use: one unusable entry
// doesn't invalidate the rest of the set.
func ParseEncryptionJWKSet(body []byte) ([]ParsedEncryptionJWK, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	var set rawJWKSet
	if err := strictjson.CheckFieldCase(body, &set); err != nil {
		return nil, fmt.Errorf("malformed jwks: %w", err)
	}
	if err := dec.Decode(&set); err != nil {
		return nil, fmt.Errorf("malformed jwks: %w", err)
	}
	var out []ParsedEncryptionJWK
	for _, raw := range set.Keys {
		key, ok := parseEncryptionEntry(raw)
		if ok {
			out = append(out, key)
		}
	}
	return out, nil
}

// parseEncryptionEntry parses one JWK Set entry as an encryption key,
// reporting false for one that isn't a usable encryption key.
func parseEncryptionEntry(data []byte) (ParsedEncryptionJWK, bool) {
	var raw rawJWK
	if strictjson.CheckFieldCase(data, &raw) != nil || json.Unmarshal(data, &raw) != nil {
		return ParsedEncryptionJWK{}, false
	}
	if raw.Use == string(jwkUseSignature) {
		return ParsedEncryptionJWK{}, false
	}
	if raw.D != nil || raw.K != nil || raw.P != nil || raw.Q != nil ||
		raw.Dp != nil || raw.Dq != nil || raw.Qi != nil {
		return ParsedEncryptionJWK{}, false
	}
	alg, ok := encryptionAlgorithmFor(raw)
	if !ok {
		return ParsedEncryptionJWK{}, false
	}
	var pub crypto.PublicKey
	var err error
	switch raw.Kty {
	case "RSA":
		pub, err = parseRSAPublicKey(raw)
	case "EC":
		var ec crypto.PublicKey
		if ec, err = parseECPublicKey(raw); err == nil {
			pub, err = ec.(*ecdsa.PublicKey).ECDH()
		}
	default:
		return ParsedEncryptionJWK{}, false
	}
	if err != nil || validateKeyForKeyManagementAlgorithm(pub, alg) != nil {
		return ParsedEncryptionJWK{}, false
	}
	return ParsedEncryptionJWK{KeyID: raw.Kid, Algorithm: alg, PublicKey: pub}, true
}

// encryptionAlgorithmFor is the key management algorithm an entry is
// for: its "alg" when that names one, or, with no "alg" but
// "use":"enc", the one its key type implies.
func encryptionAlgorithmFor(raw rawJWK) (fapi.KeyManagementAlgorithm, bool) {
	if raw.Alg != "" {
		alg, err := fapi.ParseKeyManagementAlgorithm(raw.Alg)
		return alg, err == nil
	}
	if raw.Use != string(jwkUseEncryption) {
		return 0, false
	}
	switch {
	case raw.Kty == "RSA":
		return fapi.RSAOAEP256, true
	case raw.Kty == "EC" && raw.Crv == "P-256":
		return fapi.ECDHESA256KW, true
	}
	return 0, false
}

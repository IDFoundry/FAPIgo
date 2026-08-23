package jose

import (
	"bytes"
	"crypto"
	"encoding/json"
	"fmt"

	fapi "github.com/idfoundry/fapigo"
)

// ParsedJWK is one key from a parsed JWK Set — algorithm and key ID
// alongside the public key material, before either the client (issuer
// discovery) or server (client verification) role wraps it in its own
// role-specific type. Kept intentionally minimal and un-opinionated
// about role, matching ARCHITECTURE.md's rule against sharing role-level
// types: this is a wire-format parsing result, not a role's own key
// abstraction.
type ParsedJWK struct {
	KeyID     string
	Algorithm fapi.SignatureAlgorithm
	PublicKey crypto.PublicKey
}

type rawJWKSet struct {
	Keys []json.RawMessage `json:"keys"`
}

// jwkSetAlgHint reads just enough of a JWK Set entry to decide which
// fapi.SignatureAlgorithm to validate the rest of it against —
// ParseJWK needs that algorithm as an input, since it's what determines
// which shape and size the key material must have.
type jwkSetAlgHint struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	Alg string `json:"alg,omitempty"`
	Kid string `json:"kid,omitempty"`
}

// ParseJWKSet parses a JWK Set (RFC 7517 §5) into this module's closed
// algorithm set, skipping any entry whose algorithm isn't supported or
// whose shape doesn't parse — one malformed or unsupported entry does
// not invalidate an otherwise usable key set.
func ParseJWKSet(body []byte) ([]ParsedJWK, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	var set rawJWKSet
	if err := dec.Decode(&set); err != nil {
		return nil, fmt.Errorf("malformed jwks: %w", err)
	}

	var out []ParsedJWK
	for _, raw := range set.Keys {
		var hint jwkSetAlgHint
		if err := json.Unmarshal(raw, &hint); err != nil {
			continue
		}
		alg, ok := algorithmForJWKSetHint(hint)
		if !ok {
			continue
		}
		jwk, err := ParseJWK(raw, alg)
		if err != nil {
			continue
		}
		out = append(out, ParsedJWK{KeyID: hint.Kid, Algorithm: alg, PublicKey: jwk.PublicKey()})
	}
	return out, nil
}

func algorithmForJWKSetHint(h jwkSetAlgHint) (fapi.SignatureAlgorithm, bool) {
	if h.Alg != "" {
		alg, err := fapi.ParseSignatureAlgorithm(h.Alg)
		if err != nil {
			return 0, false
		}
		return alg, true
	}
	switch h.Kty {
	case "EC":
		if h.Crv == "P-256" {
			return fapi.ES256, true
		}
		return 0, false
	case "RSA":
		return fapi.PS256, true
	case "OKP":
		if h.Crv == "Ed25519" {
			return fapi.EdDSA, true
		}
		return 0, false
	default:
		return 0, false
	}
}

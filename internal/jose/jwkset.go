package jose

import (
	"bytes"
	"crypto"
	"encoding/base64"
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

	// Certificates is the entry's own "x5c" member (RFC 7517 §4.7), if
	// present — each entry decoded from its own base64 encoding (the
	// standard alphabet §4.7 itself specifies, not base64url) into raw
	// DER bytes, but not parsed as an x509.Certificate: this package has
	// no x509-specific opinion, and a malformed entry here doesn't
	// invalidate the key material itself (ParsedJWK.PublicKey is still
	// usable) the same "one bad thing doesn't invalidate the rest"
	// stance this package's own doc comment already takes elsewhere — a
	// caller that actually needs a certificate calls
	// x509.ParseCertificate itself and handles that error. nil means the
	// entry carried no "x5c" member at all. RFC 8705 §2.2's Self-Signed
	// Certificate mutual-TLS client authentication method is the
	// motivating use (see federation/automatic_registration.go) — this
	// field is not otherwise consulted anywhere the base public key
	// material (PublicKey) already suffices.
	Certificates [][]byte
}

type rawJWKSet struct {
	Keys []json.RawMessage `json:"keys"`
}

// jwkSetAlgHint reads just enough of a JWK Set entry to decide which
// fapi.SignatureAlgorithm to validate the rest of it against — ParseJWK
// needs that algorithm as an input, since it's what determines which
// shape and size the key material must have — plus, opportunistically,
// the entry's own raw "x5c" strings (RFC 7517 §4.7), so ParseJWKSet
// doesn't need a second unmarshal pass of the same raw entry just to
// read them.
type jwkSetAlgHint struct {
	Kty string   `json:"kty"`
	Crv string   `json:"crv,omitempty"`
	Alg string   `json:"alg,omitempty"`
	Kid string   `json:"kid,omitempty"`
	X5C []string `json:"x5c,omitempty"`
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
		out = append(out, ParsedJWK{
			KeyID: hint.Kid, Algorithm: alg, PublicKey: jwk.PublicKey(),
			Certificates: decodeX5C(hint.X5C),
		})
	}
	return out, nil
}

// decodeX5C decodes each of x5c's own base64-encoded (RFC 7517 §4.7's
// own "each string in the array is a base64-encoded... DER PKIX
// certificate value" — standard alphabet, not base64url) entries into
// raw DER bytes, skipping any entry that fails to decode rather than
// discarding the rest — the same "one bad entry doesn't invalidate the
// others" stance this file's own ParsedJWK.Certificates doc comment
// describes. Returns nil, not an empty non-nil slice, when x5c itself
// was absent or every entry failed to decode, matching every other
// optional ParsedJWK field's own "absent means nil" convention.
func decodeX5C(x5c []string) [][]byte {
	if len(x5c) == 0 {
		return nil
	}
	var out [][]byte
	for _, entry := range x5c {
		der, err := base64.StdEncoding.DecodeString(entry)
		if err != nil {
			continue
		}
		out = append(out, der)
	}
	return out
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

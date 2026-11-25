package jose

import (
	"bytes"
	"crypto"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/strictb64"
	"github.com/idfoundry/fapigo/internal/strictjson"
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
	Use string   `json:"use,omitempty"`
	X5C []string `json:"x5c,omitempty"`

	KeyOps []string `json:"key_ops,omitempty"`
}

// ParseJWKSet parses a JWK Set (RFC 7517 §5)'s signature verification
// keys into this module's closed algorithm set, skipping any entry whose
// algorithm isn't supported, whose shape doesn't parse, that is marked
// "use":"enc", or whose "key_ops" (RFC 7517 §4.3) lists operations but
// not "verify" — one malformed or unsupported entry does not invalidate
// an otherwise usable key set. An entry with no "key_ops", or an empty
// one, isn't restricted by it.
//
// Its keys are treated as ones a caller supplied, like ParseJWK's: an
// RSA entry over 4096 bits (maxCallerRSAModulusBits) is skipped. Use
// ParseTrustedJWKSet for the JWK Set of a party the operator configured
// as trusted.
func ParseJWKSet(body []byte) ([]ParsedJWK, error) {
	keys, _, err := parseJWKSet(body, maxCallerRSAModulusBits)
	return keys, err
}

// SkippedJWK is a JWK Set entry ParseJWKSet skipped, and why: its "kid"
// (empty when it has none or it didn't decode) and the reason, the
// error ParseJWK gave or a description of what made it unusable. An
// entry marked "use":"enc" isn't one: it is a key for another purpose,
// not an unusable one.
type SkippedJWK struct {
	KeyID  string
	Reason error
}

// ParseJWKSetWithSkips is ParseJWKSet that also reports the entries it
// skipped, so a caller whose verification then finds no key can say
// why an entry it might have used was left out.
func ParseJWKSetWithSkips(body []byte) ([]ParsedJWK, []SkippedJWK, error) {
	return parseJWKSet(body, maxCallerRSAModulusBits)
}

// SkippedKeyReason describes, for an error saying no key answered to
// kid, why each of skipped's entries with that kid was left out: "" when
// none has it. A caller appends it to its error, so an operator reading
// "no candidate key" for a kid the set does list learns what was wrong
// with that entry. Like SkippedKeysReason, it names at most
// maxSkipReasons entries, since the set's publisher chooses how many
// there are.
func SkippedKeyReason(skipped []SkippedJWK, kid string) string {
	var matching []SkippedJWK
	for _, s := range skipped {
		if s.KeyID == kid {
			matching = append(matching, s)
		}
	}
	if len(matching) == 0 {
		return ""
	}
	return fmt.Sprintf("; the JWK Set's entry with kid %s was skipped: %s", quoteKeyID(kid), joinSkipReasons(matching, false))
}

// SkippedKeysReason is SkippedKeyReason for an error saying a set had no
// usable key at all: why its skipped entries were left out, "" when
// none was.
func SkippedKeysReason(skipped []SkippedJWK) string {
	if len(skipped) == 0 {
		return ""
	}
	return fmt.Sprintf("; %d JWK Set entries were skipped (%s)", len(skipped), joinSkipReasons(skipped, true))
}

// maxSkipReasons is how many skipped entries a reason names, and
// maxQuotedKeyIDBytes how much of a kid it quotes: both are chosen by
// whoever publishes the set, and the reason goes into an error.
const (
	maxSkipReasons      = 3
	maxQuotedKeyIDBytes = 64
)

func joinSkipReasons(skipped []SkippedJWK, withKeyIDs bool) string {
	reasons := make([]string, 0, maxSkipReasons+1)
	for i, s := range skipped {
		if i == maxSkipReasons {
			reasons = append(reasons, fmt.Sprintf("and %d more", len(skipped)-maxSkipReasons))
			break
		}
		if withKeyIDs {
			reasons = append(reasons, fmt.Sprintf("kid %s: %v", quoteKeyID(s.KeyID), s.Reason))
		} else {
			reasons = append(reasons, s.Reason.Error())
		}
	}
	return strings.Join(reasons, "; ")
}

// quoteKeyID quotes kid, or another member of an entry, cut to
// maxQuotedKeyIDBytes.
func quoteKeyID(kid string) string {
	if len(kid) > maxQuotedKeyIDBytes {
		return strconv.Quote(kid[:maxQuotedKeyIDBytes]) + "…"
	}
	return strconv.Quote(kid)
}

// ParseTrustedJWKSet is ParseJWKSet for the JWK Set of an authorization
// server the operator configured this module to trust (a client's
// issuer keys): RSA entries up to 8192 bits (maxRSAModulusBits) are
// accepted, since which server's keys get fetched is the operator's
// choice, not a caller's. Every other check is ParseJWKSet's.
func ParseTrustedJWKSet(body []byte) ([]ParsedJWK, error) {
	keys, _, err := parseJWKSet(body, maxRSAModulusBits)
	return keys, err
}

func parseJWKSet(body []byte, maxRSABits int) ([]ParsedJWK, []SkippedJWK, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	var set rawJWKSet
	if err := strictjson.CheckFieldCase(body, &set); err != nil {
		return nil, nil, fmt.Errorf("malformed jwks: %w", err)
	}
	if err := dec.Decode(&set); err != nil {
		return nil, nil, fmt.Errorf("malformed jwks: %w", err)
	}

	var (
		out     []ParsedJWK
		skipped []SkippedJWK
	)
	for _, raw := range set.Keys {
		key, skip, ok := parseJWKSetEntry(raw, maxRSABits)
		switch {
		case ok:
			out = append(out, key)
		case skip.Reason != nil:
			skipped = append(skipped, skip)
		}
	}
	return out, skipped, nil
}

// parseJWKSetEntry parses one JWK Set entry as a verification key. When
// it can't be used, ok is false and skip says why, except for an entry
// marked "use":"enc", which is skipped with no reason: it is a key for
// another purpose (RFC 7517 §4.2; see ParseEncryptionJWKSet). An entry
// whose "key_ops" (RFC 7517 §4.3) doesn't list "verify" is skipped with
// its reason (see checkKeyOps).
func parseJWKSetEntry(raw json.RawMessage, maxRSABits int) (key ParsedJWK, skip SkippedJWK, ok bool) {
	// Strictly, like ParseJWK: rawJWK doesn't model "x5c", so a case
	// variant ("X5C") would otherwise reach Certificates.
	var hint jwkSetAlgHint
	if err := strictjson.Unmarshal(raw, &hint); err != nil {
		return ParsedJWK{}, SkippedJWK{Reason: err}, false
	}
	if hint.Use == string(jwkUseEncryption) {
		return ParsedJWK{}, SkippedJWK{}, false
	}
	if err := checkKeyOps(hint.KeyOps, keyOpVerify); err != nil {
		return ParsedJWK{}, SkippedJWK{KeyID: hint.Kid, Reason: err}, false
	}
	alg, ok := algorithmForJWKSetHint(hint)
	if !ok {
		return ParsedJWK{}, SkippedJWK{KeyID: hint.Kid, Reason: fmt.Errorf("jose: unsupported key: kty %s, crv %s, alg %s", quoteKeyID(hint.Kty), quoteKeyID(hint.Crv), quoteKeyID(hint.Alg))}, false
	}
	jwk, err := parseJWK(raw, alg, maxRSABits)
	if err != nil {
		return ParsedJWK{}, SkippedJWK{KeyID: hint.Kid, Reason: err}, false
	}
	return ParsedJWK{
		KeyID: hint.Kid, Algorithm: alg, PublicKey: jwk.PublicKey(),
		Certificates: decodeX5C(hint.X5C),
	}, SkippedJWK{}, true
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
		der, err := strictb64.Std(entry)
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

package jwe

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/critical"
	"github.com/idfoundry/fapigo/internal/strictb64"
	"github.com/idfoundry/fapigo/internal/strictjson"
)

// p256CoordinateSize is the fixed byte width of an EC public key
// coordinate for P-256 — the only curve this package's ECDH-ES support
// uses, matching this module's ES256 signing convention.
const p256CoordinateSize = 32

// Header is a JWE protected header. Only the members this package's
// supported operations need are represented, but that does not make
// this a closed allow-list: RFC 7516 §4.2/§4.3 requires any Public or
// Private Header Parameter Name a recipient doesn't act on (e.g. an
// issuer's own "iss"/"aud") to be ignored, not rejected — the header
// is authenticated as JWE AAD either way, so an unrecognized
// informational member can't weaken what Decrypt checks. The one
// member enforced beyond what's modeled here is "crit" (RFC 7516
// §4.1.13, which inherits RFC 7515 §4.1.11's rule): this parser
// processes no extension parameters, so a header carrying "crit" at
// all fails to parse (see internal/critical).
type Header struct {
	Algorithm   fapi.KeyManagementAlgorithm
	Encryption  fapi.ContentEncryptionAlgorithm
	ContentType string // "cty", optional — e.g. "JWT" for a nested JWT
	KeyID       string // "kid", optional — identifies which recipient key was used

	// EphemeralPublicKey is present only for ECDH-ES-family algorithms
	// (RFC 7518 §4.6.1.1's "epk" member) — the sender's one-time public
	// key, used with the recipient's static key to derive the shared
	// secret. Always nil for RSAOAEP256.
	EphemeralPublicKey *ecdh.PublicKey

	// AgreementPartyUInfo and AgreementPartyVInfo are the decoded "apu"
	// and "apv" members (RFC 7518 §4.6.1.2/§4.6.1.3), nil when absent.
	// They're inputs to ECDH-ES key derivation (the PartyUInfo and
	// PartyVInfo fields of the Concat KDF's OtherInfo, RFC 7518
	// §4.6.2), so a sender that sets them derives a different key from
	// one that doesn't; this package feeds them into the KDF on both
	// sides. They carry no other meaning here and are unused by
	// RSAOAEP256.
	AgreementPartyUInfo []byte
	AgreementPartyVInfo []byte
}

type rawHeader struct {
	Alg  string          `json:"alg"`
	Enc  string          `json:"enc"`
	Cty  string          `json:"cty,omitempty"`
	Kid  string          `json:"kid,omitempty"`
	Epk  *rawEPK         `json:"epk,omitempty"`
	Apu  string          `json:"apu,omitempty"`
	Apv  string          `json:"apv,omitempty"`
	Crit json.RawMessage `json:"crit,omitempty"`

	// Zip is modeled only to be refused: this package never compresses
	// or decompresses (RFC 7516 §4.1.3's "zip"), so a header naming a
	// compression algorithm describes a plaintext it can't produce.
	Zip json.RawMessage `json:"zip,omitempty"`
}

// understoodExtensionParams is every extension Header Parameter this
// package processes — the set a "crit" list (RFC 7516 §4.1.13) may
// name. There are none: every member Header models is registered, and
// a registered name is never a valid "crit" entry.
var understoodExtensionParams = map[string]bool{}

// rawEPK is the wire representation of an ephemeral EC public key (RFC
// 7518 §4.6.1.1) — kty/crv/x/y only. It carries no "use", "alg" or
// "kid": those describe a key's own long-term registration, not a
// one-time value generated solely to compute this one shared secret.
type rawEPK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func marshalHeader(h Header) ([]byte, error) {
	if !h.Algorithm.IsValid() {
		return nil, fmt.Errorf("jwe: invalid key management algorithm %v", h.Algorithm)
	}
	if !h.Encryption.IsValid() {
		return nil, fmt.Errorf("jwe: invalid content encryption algorithm %v", h.Encryption)
	}
	raw := rawHeader{Alg: h.Algorithm.String(), Enc: h.Encryption.String(), Cty: h.ContentType, Kid: h.KeyID}
	if h.EphemeralPublicKey != nil {
		raw.Epk = marshalEPK(h.EphemeralPublicKey)
	}
	raw.Apu = base64.RawURLEncoding.EncodeToString(h.AgreementPartyUInfo)
	raw.Apv = base64.RawURLEncoding.EncodeToString(h.AgreementPartyVInfo)
	return json.Marshal(raw)
}

func parseHeader(data []byte) (Header, error) {
	raw, err := decodeRawHeader(data)
	if err != nil {
		return Header{}, fmt.Errorf("jwe: parse header: %w", err)
	}
	alg, err := fapi.ParseKeyManagementAlgorithm(raw.Alg)
	if err != nil {
		return Header{}, fmt.Errorf("jwe: parse header: %w", err)
	}
	enc, err := fapi.ParseContentEncryptionAlgorithm(raw.Enc)
	if err != nil {
		return Header{}, fmt.Errorf("jwe: parse header: %w", err)
	}
	h := Header{Algorithm: alg, Encryption: enc, ContentType: raw.Cty, KeyID: raw.Kid}
	if raw.Epk != nil {
		epk, err := parseEPK(raw.Epk)
		if err != nil {
			return Header{}, fmt.Errorf("jwe: parse header epk: %w", err)
		}
		h.EphemeralPublicKey = epk
	}
	if h.AgreementPartyUInfo, err = decodePartyInfo(raw.Apu); err != nil {
		return Header{}, fmt.Errorf("jwe: parse header apu: %w", err)
	}
	if h.AgreementPartyVInfo, err = decodePartyInfo(raw.Apv); err != nil {
		return Header{}, fmt.Errorf("jwe: parse header apv: %w", err)
	}
	return h, nil
}

// decodeRawHeader decodes data, a JWE protected header, refusing one
// that isn't valid UTF-8 or holds a lone surrogate escape (RFC 8725
// §3.7: encoding/json would read either as U+FFFD), repeats a member
// name at any depth (two that differ only in case count as one),
// carries a member that only case-folds to one it models, or names a
// compression algorithm, and checking its "crit". RFC 7516 §4 requires
// Header Parameter names to be unique, as RFC 7515 §4 does:
// encoding/json would merge two copies of "epk" into one key, where
// another implementation keeps one of them.
func decodeRawHeader(data []byte) (rawHeader, error) {
	var raw rawHeader
	if !strictjson.DecodesLosslessly(data) {
		return rawHeader{}, errors.New("not valid UTF-8, or an unpaired surrogate escape")
	}
	if err := strictjson.CheckDuplicateMembers(data); err != nil {
		return rawHeader{}, err
	}
	if err := strictjson.CheckFieldCase(data, &raw); err != nil {
		return rawHeader{}, err
	}
	if err := json.NewDecoder(bytes.NewReader(data)).Decode(&raw); err != nil {
		return rawHeader{}, err
	}
	if err := critical.Check(raw.Crit, understoodExtensionParams); err != nil {
		return rawHeader{}, err
	}
	if raw.Zip != nil {
		return rawHeader{}, errors.New(`compressed content ("zip") is not supported`)
	}
	return raw, nil
}

// decodePartyInfo decodes an "apu"/"apv" member as strict base64url (RFC
// 7518 §4.6.1.2: "base64url-encoded"), returning nil for an absent (or
// empty) member — either contributes an empty octet string to the
// Concat KDF's OtherInfo, so they derive the same key.
func decodePartyInfo(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	return strictb64.URL(s)
}

func marshalEPK(pub *ecdh.PublicKey) *rawEPK {
	raw := pub.Bytes() // uncompressed point: 0x04 || X || Y, each p256CoordinateSize bytes
	x := raw[1 : 1+p256CoordinateSize]
	y := raw[1+p256CoordinateSize:]
	return &rawEPK{
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(x),
		Y:   base64.RawURLEncoding.EncodeToString(y),
	}
}

func parseEPK(raw *rawEPK) (*ecdh.PublicKey, error) {
	if raw.Kty != "EC" {
		return nil, fmt.Errorf("unsupported epk key type %q", raw.Kty)
	}
	if raw.Crv != "P-256" {
		return nil, fmt.Errorf("unsupported epk curve %q", raw.Crv)
	}
	x, err := decodeCoordinate(raw.X)
	if err != nil {
		return nil, fmt.Errorf("decode epk x: %w", err)
	}
	y, err := decodeCoordinate(raw.Y)
	if err != nil {
		return nil, fmt.Errorf("decode epk y: %w", err)
	}
	uncompressed := slices.Concat([]byte{0x04}, x, y) // SEC 1 §2.3.3
	pub, err := ecdh.P256().NewPublicKey(uncompressed)
	if err != nil {
		return nil, fmt.Errorf("invalid epk point: %w", err)
	}
	return pub, nil
}

// decodeCoordinate decodes an epk's "x" or "y", which RFC 7518 §6.2.1.2
// and §6.2.1.3 require to be exactly p256CoordinateSize octets, leading
// zero octets included: a coordinate of any other length is refused,
// even one encoding a point on the curve, rather than padded or
// trimmed into one, as internal/jose refuses it in a JWK.
func decodeCoordinate(s string) ([]byte, error) {
	if s == "" {
		return nil, fmt.Errorf("empty value")
	}
	b, err := strictb64.URL(s)
	if err != nil {
		return nil, err
	}
	if len(b) != p256CoordinateSize {
		return nil, fmt.Errorf("%d octets, not the %d of a P-256 coordinate", len(b), p256CoordinateSize)
	}
	return b, nil
}

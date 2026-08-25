package jwe

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"

	fapi "github.com/idfoundry/fapigo"
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
// §4.1.13, which inherits RFC 7515 §4.1.11's rule): every name it
// lists must be one this parser actually understands and processes,
// or parsing fails outright.
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
}

type rawHeader struct {
	Alg  string   `json:"alg"`
	Enc  string   `json:"enc"`
	Cty  string   `json:"cty,omitempty"`
	Kid  string   `json:"kid,omitempty"`
	Epk  *rawEPK  `json:"epk,omitempty"`
	Crit []string `json:"crit,omitempty"`
}

// understoodHeaderParams is every JWE Header Parameter name this
// package's Header type models and processes — the set a "crit" list
// (RFC 7516 §4.1.13) is checked against.
var understoodHeaderParams = map[string]bool{
	"alg": true, "enc": true, "cty": true, "kid": true, "epk": true, "crit": true,
}

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
	return json.Marshal(raw)
}

func parseHeader(data []byte) (Header, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	var raw rawHeader
	if err := dec.Decode(&raw); err != nil {
		return Header{}, fmt.Errorf("jwe: parse header: %w", err)
	}
	for _, name := range raw.Crit {
		if !understoodHeaderParams[name] {
			return Header{}, fmt.Errorf("jwe: parse header: critical header parameter %q is not understood", name)
		}
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
	return h, nil
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
	// x/y are attacker-controlled at this point (this function parses an
	// untrusted header); big.Int.FillBytes below panics if the value
	// doesn't fit in p256CoordinateSize bytes, so that must be rejected
	// as a plain error first, not left to crash on a malformed epk.
	if x.BitLen() > 8*p256CoordinateSize || y.BitLen() > 8*p256CoordinateSize {
		return nil, fmt.Errorf("epk coordinate exceeds P-256 field size")
	}
	uncompressed := make([]byte, 1+2*p256CoordinateSize)
	uncompressed[0] = 0x04
	x.FillBytes(uncompressed[1 : 1+p256CoordinateSize])
	y.FillBytes(uncompressed[1+p256CoordinateSize:])
	pub, err := ecdh.P256().NewPublicKey(uncompressed)
	if err != nil {
		return nil, fmt.Errorf("invalid epk point: %w", err)
	}
	return pub, nil
}

func decodeCoordinate(s string) (*big.Int, error) {
	if s == "" {
		return nil, fmt.Errorf("empty value")
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}

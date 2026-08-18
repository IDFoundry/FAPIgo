package jose

import (
	"bytes"
	"encoding/json"
	"fmt"

	fapi "github.com/idfoundry/fapigo"
)

// Header is a JWS protected header. Only the members this module's
// supported operations need are represented. Parsing rejects any header
// member not listed here — a JWS header is part of what the signature
// protects, so an unrecognized member (e.g. "crit", "cty") is refused
// rather than silently ignored.
type Header struct {
	Algorithm fapi.SignatureAlgorithm
	Type      string // "typ", optional
	KeyID     string // "kid", optional
	JWK       *JWK   // "jwk", optional — an embedded public key (used by DPoP)
}

type rawHeader struct {
	Alg string          `json:"alg"`
	Typ string          `json:"typ,omitempty"`
	Kid string          `json:"kid,omitempty"`
	Jwk json.RawMessage `json:"jwk,omitempty"`
}

func marshalHeader(h Header) ([]byte, error) {
	if !h.Algorithm.IsValid() {
		return nil, fmt.Errorf("jose: invalid algorithm %v", h.Algorithm)
	}
	raw := rawHeader{Alg: h.Algorithm.String(), Typ: h.Type, Kid: h.KeyID}
	if h.JWK != nil {
		jwkJSON, err := h.JWK.MarshalJSON()
		if err != nil {
			return nil, fmt.Errorf("jose: marshal header jwk: %w", err)
		}
		raw.Jwk = jwkJSON
	}
	return json.Marshal(raw)
}

func parseHeader(data []byte) (Header, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var raw rawHeader
	if err := dec.Decode(&raw); err != nil {
		return Header{}, fmt.Errorf("jose: parse header: %w", err)
	}
	alg, err := fapi.ParseSignatureAlgorithm(raw.Alg)
	if err != nil {
		return Header{}, fmt.Errorf("jose: parse header: %w", err)
	}
	h := Header{Algorithm: alg, Type: raw.Typ, KeyID: raw.Kid}
	if len(raw.Jwk) > 0 {
		jwk, err := ParseJWK(raw.Jwk, alg)
		if err != nil {
			return Header{}, fmt.Errorf("jose: parse header jwk: %w", err)
		}
		h.JWK = &jwk
	}
	return h, nil
}

package jose

import (
	"bytes"
	"encoding/json"
	"fmt"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/critical"
)

// Header is a JWS protected header. Only the members this module's
// supported operations need are represented, but that does not make
// this a closed allow-list: RFC 7515 §4.2/§4.3 requires any Public or
// Private Header Parameter Name a recipient doesn't act on (e.g.
// "x5c", "cty") to be ignored, not rejected — the header is entirely
// signature-covered, so an unrecognized informational member can't
// weaken what Verify checks. The one member enforced beyond what's
// modeled here is "crit" (RFC 7515 §4.1.11): every name it lists must
// be one this parser actually understands and processes, or parsing
// fails outright — an issuer marking something critical that this
// package doesn't act on is exactly the case "crit" exists to catch.
type Header struct {
	Algorithm fapi.SignatureAlgorithm
	Type      string // "typ", optional
	KeyID     string // "kid", optional
	JWK       *JWK   // "jwk", optional — an embedded public key (used by DPoP)
}

type rawHeader struct {
	Alg  string          `json:"alg"`
	Typ  string          `json:"typ,omitempty"`
	Kid  string          `json:"kid,omitempty"`
	Jwk  json.RawMessage `json:"jwk,omitempty"`
	Crit []string        `json:"crit,omitempty"`
}

// understoodHeaderParams is every JWS Header Parameter name this
// package's Header type models and processes — the set a "crit" list
// (RFC 7515 §4.1.11) is checked against. A name here is deliberately
// not the same thing as "every registered JWS header parameter": this
// package only claims to understand what it actually parses and acts
// on above.
var understoodHeaderParams = map[string]bool{
	"alg": true, "typ": true, "kid": true, "jwk": true, "crit": true,
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
	var raw rawHeader
	if err := dec.Decode(&raw); err != nil {
		return Header{}, fmt.Errorf("jose: parse header: %w", err)
	}
	if err := critical.Check(raw.Crit, understoodHeaderParams); err != nil {
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

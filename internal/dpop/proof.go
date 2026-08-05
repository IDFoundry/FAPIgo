package dpop

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// jwtType is the required JWS "typ" header value for a DPoP proof
// (RFC 9449 §4.2).
const jwtType = "dpop+jwt"

// claims is the DPoP proof payload (RFC 9449 §4.2). Fields beyond the
// ones defined here are rejected on parse — a proof carrying an
// unexpected claim is refused rather than silently ignored.
type claims struct {
	JTI   string `json:"jti"`
	HTM   string `json:"htm"`
	HTU   string `json:"htu"`
	IAT   int64  `json:"iat"`
	ATH   string `json:"ath,omitempty"`
	Nonce string `json:"nonce,omitempty"`
}

func parseClaims(payload []byte) (claims, error) {
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	var c claims
	if err := dec.Decode(&c); err != nil {
		return claims{}, fmt.Errorf("%w: %v", ErrMalformedClaims, err)
	}
	if c.JTI == "" || c.HTM == "" || c.HTU == "" {
		return claims{}, ErrMalformedClaims
	}
	return c, nil
}

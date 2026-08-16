package dpop

import (
	"encoding/json"
	"fmt"
)

// jwtType is the required JWS "typ" header value for a DPoP proof
// (RFC 9449 §4.2).
const jwtType = "dpop+jwt"

// claims is the DPoP proof payload (RFC 9449 §4.2). Unrecognized fields
// are tolerated, not rejected: a DPoP proof is a JWT, and general JWT
// claim extensibility (RFC 7519 §4) permits a sender to include
// additional claims (registered, e.g. nbf/exp, or private) that this
// verifier has no opinion on. Verify relies on Iat for freshness.
type claims struct {
	JTI   string `json:"jti"`
	HTM   string `json:"htm"`
	HTU   string `json:"htu"`
	IAT   int64  `json:"iat"`
	ATH   string `json:"ath,omitempty"`
	Nonce string `json:"nonce,omitempty"`
}

func parseClaims(payload []byte) (claims, error) {
	var c claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return claims{}, fmt.Errorf("%w: %v", ErrMalformedClaims, err)
	}
	if c.JTI == "" || c.HTM == "" || c.HTU == "" {
		return claims{}, ErrMalformedClaims
	}
	return c, nil
}

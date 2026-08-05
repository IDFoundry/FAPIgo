package clientassertion

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// AssertionType is the required client_assertion_type value (RFC 7523
// §2.2) for a JWT bearer client assertion. Callers should check an
// inbound client_assertion_type form parameter against this constant
// before attempting to parse client_assertion as an assertion at all.
const AssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// claims is a client assertion payload (RFC 7523 §3). Fields beyond the
// ones defined here are rejected on parse. aud is required to be a
// single JSON string; this package does not accept a JSON array for aud,
// which removes any ambiguity about which of several audiences a token
// was actually intended for.
type claims struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Audience  string `json:"aud"`
	JTI       string `json:"jti"`
	ExpiresAt int64  `json:"exp"`
	IssuedAt  int64  `json:"iat,omitempty"`
	NotBefore int64  `json:"nbf,omitempty"`
}

func parseClaims(payload []byte) (claims, error) {
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	var c claims
	if err := dec.Decode(&c); err != nil {
		return claims{}, fmt.Errorf("%w: %v", ErrMalformedClaims, err)
	}
	if c.Issuer == "" || c.Subject == "" || c.Audience == "" || c.JTI == "" || c.ExpiresAt == 0 {
		return claims{}, ErrMalformedClaims
	}
	return c, nil
}

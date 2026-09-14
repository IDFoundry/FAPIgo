package clientattestation

import (
	"encoding/json"
	"fmt"
)

// attestationClaims is the Client Attestation JWT's claims set
// (draft-07 §5.1). Unlike clientassertion.claims, unrecognized claims
// are tolerated and ignored — §5.1 rule 1: "The JWT MAY contain other
// claims. All claims that are not understood by implementations MUST
// be ignored." json.Unmarshal's default behavior already does this, so
// (deliberately, unlike clientassertion.claims) this type never calls
// json.Decoder.DisallowUnknownFields.
type attestationClaims struct {
	Issuer       string             `json:"iss"`
	Subject      string             `json:"sub"`
	ExpiresAt    int64              `json:"exp"`
	IssuedAt     int64              `json:"iat,omitempty"`
	NotBefore    int64              `json:"nbf,omitempty"`
	Confirmation confirmationClaims `json:"cnf"`
}

// confirmationClaims is the cnf claim's "jwk" member (RFC 7800 §3.2).
// JWK is kept as raw JSON, not parsed here — see
// VerifiedAttestation.ConfirmationJWK's own doc comment for why.
type confirmationClaims struct {
	JWK json.RawMessage `json:"jwk"`
}

func parseAttestationClaims(payload []byte) (attestationClaims, error) {
	var c attestationClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return attestationClaims{}, fmt.Errorf("%w: %v", ErrMalformedClaims, err)
	}
	if c.Issuer == "" || c.Subject == "" || c.ExpiresAt == 0 || len(c.Confirmation.JWK) == 0 {
		return attestationClaims{}, ErrMalformedClaims
	}
	return c, nil
}

// popClaims is the Client Attestation PoP JWT's claims set (draft-07
// §5.2). Like attestationClaims, unrecognized claims are tolerated and
// ignored (§5.2 rule 1). aud is required to be a single JSON string —
// this package does not accept a JSON array, the same restriction
// clientassertion.claims applies to its own aud claim and for the same
// reason: it removes any ambiguity about which of several audiences a
// token was actually intended for.
type popClaims struct {
	Issuer    string `json:"iss"`
	Audience  string `json:"aud"`
	JTI       string `json:"jti"`
	IssuedAt  int64  `json:"iat"`
	Challenge string `json:"challenge,omitempty"`
	NotBefore int64  `json:"nbf,omitempty"`
}

func parsePoPClaims(payload []byte) (popClaims, error) {
	var c popClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return popClaims{}, fmt.Errorf("%w: %v", ErrMalformedClaims, err)
	}
	if c.Issuer == "" || c.Audience == "" || c.JTI == "" || c.IssuedAt == 0 {
		return popClaims{}, ErrMalformedClaims
	}
	return c, nil
}

package clientattestation

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/idfoundry/fapigo/internal/strictjson"
)

// attestationClaims is the Client Attestation JWT's claims set (draft-12
// §4). Unlike clientassertion.claims, unrecognized claims are tolerated
// and ignored — §4 rule 1: "The JWT MAY contain other claims. All
// claims that are not understood by implementations MUST be ignored."
// json.Unmarshal's default behavior already does this, so (deliberately,
// unlike clientassertion.claims) this type never calls
// json.Decoder.DisallowUnknownFields.
//
// iss is optional: draft-07 required it, naming the Attester, and
// draft-08 removed it. An attestation is accepted with or without it;
// see Attestation.Verify for how one that has it is still checked. iat
// is likewise optional here, though draft-12 requires it, so attesters
// following draft-07 keep working.
type attestationClaims struct {
	Issuer       string             `json:"iss,omitempty"`
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
	if err := strictjson.Unmarshal(payload, &c); err != nil {
		return attestationClaims{}, fmt.Errorf("%w: %v", ErrMalformedClaims, err)
	}
	if c.Subject == "" || c.ExpiresAt == 0 || len(c.Confirmation.JWK) == 0 {
		return attestationClaims{}, ErrMalformedClaims
	}
	return c, nil
}

// popClaims is the Client Attestation PoP JWT's claims set (draft-12
// §5.1). Like attestationClaims, unrecognized claims are tolerated and
// ignored (§5.1 rule 1).
//
// iss is optional: draft-07 required it, naming the client, and draft-08
// removed it; see PoP.Verify. exp isn't one of the PoP's own claims in
// either draft, but a PoP that carries one is held to it (§5.1 rule 4:
// "MUST reject a JWT that is not valid in all other respects per" RFC
// 7519).
type popClaims struct {
	Issuer    string      `json:"iss,omitempty"`
	Audience  popAudience `json:"aud"`
	JTI       string      `json:"jti"`
	IssuedAt  int64       `json:"iat"`
	ExpiresAt int64       `json:"exp,omitempty"`
	Challenge string      `json:"challenge,omitempty"`
	NotBefore int64       `json:"nbf,omitempty"`
}

// popAudience is a PoP's aud claim: one audience, as a JSON string or as
// an array holding exactly that one string. RFC 7519 §4.1.3 allows
// either form; draft-12 §5.1 says a PoP "is intended for a single
// audience" and that clients "MUST generate a separate JWT for each
// target", so an array naming more than one audience is refused rather
// than searched. It marshals as a string.
type popAudience string

func (a *popAudience) UnmarshalJSON(data []byte) error {
	if bytes.HasPrefix(bytes.TrimLeft(data, " \t\r\n"), []byte("[")) {
		var many []string
		if err := json.Unmarshal(data, &many); err != nil {
			return err
		}
		if len(many) != 1 {
			return errors.New("aud must name exactly one audience")
		}
		*a = popAudience(many[0])
		return nil
	}
	var one string
	if err := json.Unmarshal(data, &one); err != nil {
		return err
	}
	*a = popAudience(one)
	return nil
}

func parsePoPClaims(payload []byte) (popClaims, error) {
	var c popClaims
	if err := strictjson.Unmarshal(payload, &c); err != nil {
		return popClaims{}, fmt.Errorf("%w: %v", ErrMalformedClaims, err)
	}
	if c.Audience == "" || c.JTI == "" || c.IssuedAt == 0 {
		return popClaims{}, ErrMalformedClaims
	}
	return c, nil
}

package clientassertion

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/idfoundry/fapigo/internal/numericdate"
	"github.com/idfoundry/fapigo/internal/strictjson"
)

// AssertionType is the required client_assertion_type value (RFC 7523
// §2.2) for a JWT bearer client assertion. Callers should check an
// inbound client_assertion_type form parameter against this constant
// before attempting to parse client_assertion as an assertion at all.
const AssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// clientAuthenticationJWTType is the explicit "typ" draft-ietf-oauth-
// rfc7523bis gives a client authentication assertion: accepted, like a
// missing or generic typ, while another kind's explicit typ isn't.
const clientAuthenticationJWTType = "client-authentication+jwt"

// requestClaims are the authorization and CIBA request parameters
// (RFC 6749 §4.1.1, RFC 7636 §4.3, RFC 9101 §5, RFC 9396 §2, OIDC Core
// §3.1.2.1 and §5.5, CIBA Core §7.1) that a request object or a CIBA
// signed request carries and a client assertion has no use for. The
// client signs all three kinds with one key set, so an assertion
// carrying one of these is a signed request presented as an assertion
// (RFC 8725 §3.12), not an assertion, and parseClaims refuses it.
var requestClaims = []string{
	"response_type", "redirect_uri", "scope", "state", "nonce",
	"code_challenge", "request", "request_uri", "claims", "authorization_details",
	"login_hint", "login_hint_token", "id_token_hint", "binding_message", "client_notification_token",
}

// claims is a client assertion payload (RFC 7523 §3). Claims beyond the
// ones defined here are ignored — RFC 7523 §3 item 8 says the JWT "MAY
// contain other claims", and RFC 7519 §4 has a claim that isn't
// understood ignored — except requestClaims, which are refused. aud is
// required to be a
// single JSON string; this package does not accept a JSON array for aud,
// which removes any ambiguity about which of several audiences a token
// was actually intended for.
type claims struct {
	Issuer    string            `json:"iss"`
	Subject   string            `json:"sub"`
	Audience  string            `json:"aud"`
	JTI       string            `json:"jti"`
	ExpiresAt numericdate.Value `json:"exp"`
	IssuedAt  numericdate.Value `json:"iat,omitempty"`
	NotBefore numericdate.Value `json:"nbf,omitempty"`
}

func parseClaims(payload []byte) (claims, error) {
	dec := json.NewDecoder(bytes.NewReader(payload))
	var c claims
	if err := strictjson.CheckFieldCase(payload, &c); err != nil {
		return claims{}, fmt.Errorf("%w: %v", ErrMalformedClaims, err)
	}
	if err := dec.Decode(&c); err != nil {
		return claims{}, fmt.Errorf("%w: %v", ErrMalformedClaims, err)
	}
	if err := refuseRequestClaims(payload); err != nil {
		return claims{}, err
	}
	if c.Issuer == "" || c.Subject == "" || c.Audience == "" || c.JTI == "" || c.ExpiresAt == 0 {
		return claims{}, ErrMalformedClaims
	}
	return c, nil
}

// refuseRequestClaims returns ErrRequestClaim when payload carries any
// of requestClaims. parseClaims has already decoded payload as a JSON
// object (or null, which has no members and fails its own checks), so
// decoding it again as one can't fail.
func refuseRequestClaims(payload []byte) error {
	var members map[string]json.RawMessage
	_ = json.Unmarshal(payload, &members)
	for _, name := range requestClaims {
		if _, ok := members[name]; ok {
			return fmt.Errorf("%w: %q", ErrRequestClaim, name)
		}
	}
	return nil
}

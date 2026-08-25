package token

import (
	"encoding/json"
	"fmt"
	"time"
)

// IDTokenClaims is a parsed ID token payload (OIDC Core §2).
//
// Audience is a slice because OIDC Core §2 explicitly documents "aud" as
// possibly multi-valued for an ID token ("In the general case, the aud
// value is an array of case sensitive strings" — a single string is
// just the one-element case) — unlike internal/clientassertion's own
// Audience, which stays a single string because a client assertion is
// always addressed to exactly one token endpoint, never several
// audiences at once. §3.1.3.7 step 9 additionally says a client "SHOULD
// verify that an azp Claim is present" when there's more than one
// audience, and step 10 that it "SHOULD verify" azp equals the client's
// own ID when present — IDTokenValidatePolicy.Validate enforces both.
//
// Everything beyond the claims this struct names is left in Parameters
// as raw JSON.
type IDTokenClaims struct {
	Issuer    string
	Subject   string
	Audience  []string
	ExpiresAt time.Time
	IssuedAt  time.Time
	Nonce     string    // "" if absent
	AuthTime  time.Time // zero if absent
	ACR       string    // "" if absent
	AMR       []string  // nil if absent
	AZP       string    // "" if absent

	Parameters map[string]json.RawMessage
}

func parseIDTokenClaims(payload []byte) (IDTokenClaims, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil {
		return IDTokenClaims{}, fmt.Errorf("%w: %v", ErrMalformedClaims, err)
	}

	iss, _, err := popString(raw, "iss", true)
	if err != nil {
		return IDTokenClaims{}, err
	}
	sub, _, err := popString(raw, "sub", true)
	if err != nil {
		return IDTokenClaims{}, err
	}
	aud, err := popStringOrStringSlice(raw, "aud")
	if err != nil {
		return IDTokenClaims{}, err
	}
	exp, _, err := popInt64(raw, "exp", true)
	if err != nil {
		return IDTokenClaims{}, err
	}
	iat, _, err := popInt64(raw, "iat", true)
	if err != nil {
		return IDTokenClaims{}, err
	}
	nonce, _, err := popString(raw, "nonce", false)
	if err != nil {
		return IDTokenClaims{}, err
	}
	authTime, hasAuthTime, err := popInt64(raw, "auth_time", false)
	if err != nil {
		return IDTokenClaims{}, err
	}
	acr, _, err := popString(raw, "acr", false)
	if err != nil {
		return IDTokenClaims{}, err
	}
	amr, _, err := popStringSlice(raw, "amr")
	if err != nil {
		return IDTokenClaims{}, err
	}
	azp, _, err := popString(raw, "azp", false)
	if err != nil {
		return IDTokenClaims{}, err
	}

	c := IDTokenClaims{
		Issuer:     iss,
		Subject:    sub,
		Audience:   aud,
		ExpiresAt:  time.Unix(exp, 0),
		IssuedAt:   time.Unix(iat, 0),
		Nonce:      nonce,
		ACR:        acr,
		AMR:        amr,
		AZP:        azp,
		Parameters: raw,
	}
	if hasAuthTime {
		c.AuthTime = time.Unix(authTime, 0)
	}
	return c, nil
}

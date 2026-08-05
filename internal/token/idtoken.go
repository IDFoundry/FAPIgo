package token

import (
	"encoding/json"
	"fmt"
	"time"
)

// IDTokenClaims is a parsed ID token payload (OIDC Core §2). Audience is
// restricted to a single value — see the equivalent restriction and
// rationale in internal/clientassertion. Everything beyond the claims
// this struct names is left in Parameters as raw JSON.
type IDTokenClaims struct {
	Issuer    string
	Subject   string
	Audience  string
	ExpiresAt time.Time
	IssuedAt  time.Time
	Nonce     string    // "" if absent
	AuthTime  time.Time // zero if absent
	ACR       string    // "" if absent
	AMR       []string  // nil if absent

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
	aud, _, err := popString(raw, "aud", true)
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

	c := IDTokenClaims{
		Issuer:     iss,
		Subject:    sub,
		Audience:   aud,
		ExpiresAt:  time.Unix(exp, 0),
		IssuedAt:   time.Unix(iat, 0),
		Nonce:      nonce,
		ACR:        acr,
		AMR:        amr,
		Parameters: raw,
	}
	if hasAuthTime {
		c.AuthTime = time.Unix(authTime, 0)
	}
	return c, nil
}

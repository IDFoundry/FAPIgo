package requestobject

import (
	"encoding/json"
	"fmt"
	"time"
)

// jwtType is the required JWS "typ" header value for a request object
// (RFC 9101 §10.8), which exists specifically to stop a request object
// from being confused with — or accepted as — any other kind of JWT.
const jwtType = "oauth-authz-req+jwt"

// Claims is a parsed request object payload. iss, aud and exp are the
// JWT-standard claims RFC 9101 relies on; everything else — the actual
// authorization request parameters (response_type, client_id,
// redirect_uri, scope, state, nonce, code_challenge,
// code_challenge_method, authorization_details, and any registered
// extension parameter) — is left in Parameters as raw JSON for the
// extension/RAR layer to interpret against its own registered
// definitions. This package does not reject unrecognized parameter
// names; deciding which parameters are allowed is policy that belongs
// above this package.
type Claims struct {
	Issuer     string
	Audience   string
	ExpiresAt  time.Time
	IssuedAt   time.Time // zero if absent
	NotBefore  time.Time // zero if absent
	JTI        string    // "" if absent
	Parameters map[string]json.RawMessage
}

func parseClaims(payload []byte) (Claims, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil {
		return Claims{}, fmt.Errorf("%w: %v", ErrMalformedClaims, err)
	}

	iss, _, err := popString(raw, "iss", true)
	if err != nil {
		return Claims{}, err
	}
	aud, _, err := popString(raw, "aud", true)
	if err != nil {
		return Claims{}, err
	}
	exp, _, err := popInt64(raw, "exp", true)
	if err != nil {
		return Claims{}, err
	}
	nbf, hasNbf, err := popInt64(raw, "nbf", false)
	if err != nil {
		return Claims{}, err
	}
	iat, hasIat, err := popInt64(raw, "iat", false)
	if err != nil {
		return Claims{}, err
	}
	jti, _, err := popString(raw, "jti", false)
	if err != nil {
		return Claims{}, err
	}

	if clientIDRaw, ok := raw["client_id"]; ok {
		var clientID string
		if err := json.Unmarshal(clientIDRaw, &clientID); err != nil {
			return Claims{}, fmt.Errorf("%w: client_id: %v", ErrMalformedClaims, err)
		}
		if clientID != iss {
			return Claims{}, ErrClientIDIssuerMismatch
		}
	}

	c := Claims{
		Issuer:     iss,
		Audience:   aud,
		ExpiresAt:  time.Unix(exp, 0),
		JTI:        jti,
		Parameters: raw,
	}
	if hasNbf {
		c.NotBefore = time.Unix(nbf, 0)
	}
	if hasIat {
		c.IssuedAt = time.Unix(iat, 0)
	}
	return c, nil
}

// popString extracts and deletes key from m, decoding it as a JSON
// string. If required and the key is absent, it returns
// ErrMalformedClaims.
func popString(m map[string]json.RawMessage, key string, required bool) (value string, present bool, err error) {
	raw, ok := m[key]
	if !ok {
		if required {
			return "", false, fmt.Errorf("%w: missing %q", ErrMalformedClaims, key)
		}
		return "", false, nil
	}
	delete(m, key)
	var s string
	if err := json.Unmarshal(raw, &s); err != nil || s == "" {
		return "", false, fmt.Errorf("%w: %q must be a non-empty string", ErrMalformedClaims, key)
	}
	return s, true, nil
}

// popInt64 extracts and deletes key from m, decoding it as a JSON
// number. If required and the key is absent, it returns
// ErrMalformedClaims.
func popInt64(m map[string]json.RawMessage, key string, required bool) (value int64, present bool, err error) {
	raw, ok := m[key]
	if !ok {
		if required {
			return 0, false, fmt.Errorf("%w: missing %q", ErrMalformedClaims, key)
		}
		return 0, false, nil
	}
	delete(m, key)
	var n int64
	if err := json.Unmarshal(raw, &n); err != nil {
		return 0, false, fmt.Errorf("%w: %q must be an integer", ErrMalformedClaims, key)
	}
	return n, true, nil
}

package jarm

import (
	"encoding/json"
	"fmt"
	"time"
)

// Claims is a parsed JARM response payload. iss, aud and exp are the
// JWT-standard claims JARM relies on; everything else — the actual
// authorization response parameters (code, state, error,
// error_description, error_uri, and any extension parameter) — is left
// in Parameters as raw JSON. This package treats a success response and
// an error response identically: both are signed the same way and
// validated the same way, which is what stops a spoofed error response
// from bypassing the integrity check a success response gets.
type Claims struct {
	Issuer     string
	Audience   string
	ExpiresAt  time.Time
	IssuedAt   time.Time // zero if absent
	NotBefore  time.Time // zero if absent
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

	c := Claims{
		Issuer:     iss,
		Audience:   aud,
		ExpiresAt:  time.Unix(exp, 0),
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

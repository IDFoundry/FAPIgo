package requestobject

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// jwtType is the JWS "typ" header value Create always sets on a request
// object it signs (RFC 9101 §10.8), which exists specifically to stop a
// request object from being confused with — or accepted as — any other
// kind of JWT. Parse, however, only rejects a "typ" that is present and
// wrong, not one that's simply absent: §10.8 explicitly frames explicit
// typing as something "one would" do, not a requirement, and warns that
// "requiring explicitly typed Request Objects at existing authorization
// servers will break most existing deployments, as existing clients are
// already commonly using untyped Request Objects" — so an absent "typ"
// must still be accepted.
const jwtType = "oauth-authz-req+jwt"

// isRequestObjectType reports whether typ, a present-and-non-empty JWS
// "typ" header value, identifies a request object. RFC 7515 §4.1.9 and
// §5.3 single "typ" out as the one JOSE header value NOT subject to
// ordinary case-sensitive JSON string comparison — it follows RFC 2045
// media-type comparison rules instead, which are explicitly case
// insensitive, and a value with no "/" is treated as if "application/"
// had been prepended (matching RFC 9101 §10.8's own recommendation to
// omit that prefix). The OIDF conformance suite deliberately sends a
// randomized-case "typ" for exactly this reason (JAR-4) — a naive exact
// comparison rejects a spec-compliant request object.
func isRequestObjectType(typ string) bool {
	typ = strings.TrimPrefix(strings.ToLower(typ), "application/")
	return typ == jwtType
}

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
	Issuer string

	// Audience is the object's "aud" claim. RFC 7519 §4.1.3 permits a
	// JWT's "aud" to be either a single string or an array of strings —
	// both are normalized to this slice, so Verify's audience check
	// treats a single value the same as a one-element array.
	Audience   []string
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
	aud, err := popStringOrArray(raw, "aud")
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

// popStringOrArray extracts and deletes "aud" from m, accepting either
// form RFC 7519 §4.1.3 permits: a single JSON string, or a JSON array
// of one or more non-empty strings. It is required — a request object
// missing "aud" entirely is malformed either way.
func popStringOrArray(m map[string]json.RawMessage, key string) ([]string, error) {
	raw, ok := m[key]
	if !ok {
		return nil, fmt.Errorf("%w: missing %q", ErrMalformedClaims, key)
	}
	delete(m, key)

	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if s == "" {
			return nil, fmt.Errorf("%w: %q must be a non-empty string", ErrMalformedClaims, key)
		}
		return []string{s}, nil
	}

	var arr []string
	if err := json.Unmarshal(raw, &arr); err != nil || len(arr) == 0 {
		return nil, fmt.Errorf("%w: %q must be a non-empty string or a non-empty array of strings", ErrMalformedClaims, key)
	}
	for _, v := range arr {
		if v == "" {
			return nil, fmt.Errorf("%w: %q must not contain an empty string", ErrMalformedClaims, key)
		}
	}
	return arr, nil
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

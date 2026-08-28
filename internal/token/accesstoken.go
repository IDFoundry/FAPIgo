package token

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

// atJWTType is the required JWS "typ" header value for a JWT access
// token (RFC 9068 §2.1) — it exists to stop an access token from being
// confused with, or accepted as, any other kind of JWT.
const atJWTType = "at+jwt"

// Confirmation is the RFC 7800 "cnf" claim used to record a sender
// constraint on an access token — exactly one of JKT (DPoP key
// thumbprint, RFC 9449 §6.1) or X5TS256 (mTLS certificate thumbprint,
// RFC 8705 §3.1) is ever set on a given token, never both: a token is
// bound exactly one way.
type Confirmation struct {
	JKT     string
	X5TS256 string
}

// AccessTokenClaims is a parsed JWT access token payload (RFC 9068).
// Audience is a slice because RFC 9068 §3 does not narrow RFC 7519
// §4.1.3's general "aud" definition, which permits either a single
// string or an array — unlike internal/clientassertion's own Audience,
// which stays a single string because a client assertion is always
// addressed to exactly one token endpoint, never several audiences at
// once. Everything beyond the claims RFC 9068 defines — most
// importantly a granted authorization_details (RFC 9396) — is left in
// Parameters as raw JSON.
type AccessTokenClaims struct {
	Issuer       string
	Subject      string
	Audience     []string
	ClientID     string
	Scope        string // space-delimited; "" if absent
	ExpiresAt    time.Time
	IssuedAt     time.Time
	JTI          string
	Confirmation *Confirmation // nil if the token is not sender-constrained
	Parameters   map[string]json.RawMessage
}

type rawConfirmation struct {
	JKT     string `json:"jkt,omitempty"`
	X5TS256 string `json:"x5t#S256,omitempty"`
}

func parseAccessTokenClaims(payload []byte) (AccessTokenClaims, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil {
		return AccessTokenClaims{}, fmt.Errorf("%w: %v", ErrMalformedClaims, err)
	}

	iss, _, err := popString(raw, "iss", true)
	if err != nil {
		return AccessTokenClaims{}, err
	}
	sub, _, err := popString(raw, "sub", true)
	if err != nil {
		return AccessTokenClaims{}, err
	}
	aud, err := popStringOrStringSlice(raw, "aud")
	if err != nil {
		return AccessTokenClaims{}, err
	}
	clientID, _, err := popString(raw, "client_id", true)
	if err != nil {
		return AccessTokenClaims{}, err
	}
	exp, _, err := popInt64(raw, "exp", true)
	if err != nil {
		return AccessTokenClaims{}, err
	}
	iat, _, err := popInt64(raw, "iat", true)
	if err != nil {
		return AccessTokenClaims{}, err
	}
	jti, _, err := popString(raw, "jti", true)
	if err != nil {
		return AccessTokenClaims{}, err
	}
	scope, _, err := popString(raw, "scope", false)
	if err != nil {
		return AccessTokenClaims{}, err
	}

	var confirmation *Confirmation
	if cnfRaw, ok := raw["cnf"]; ok {
		delete(raw, "cnf")
		dec := json.NewDecoder(bytes.NewReader(cnfRaw))
		dec.DisallowUnknownFields()
		var c rawConfirmation
		// Exactly one of jkt/x5t#S256 — a token is bound exactly one
		// way, never both and never neither.
		if err := dec.Decode(&c); err != nil || (c.JKT == "") == (c.X5TS256 == "") {
			return AccessTokenClaims{}, fmt.Errorf("%w: cnf must be an object with exactly one of a non-empty jkt or x5t#S256", ErrMalformedClaims)
		}
		confirmation = &Confirmation{JKT: c.JKT, X5TS256: c.X5TS256}
	}

	return AccessTokenClaims{
		Issuer:       iss,
		Subject:      sub,
		Audience:     aud,
		ClientID:     clientID,
		Scope:        scope,
		ExpiresAt:    time.Unix(exp, 0),
		IssuedAt:     time.Unix(iat, 0),
		JTI:          jti,
		Confirmation: confirmation,
		Parameters:   raw,
	}, nil
}

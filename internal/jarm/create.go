package jarm

import (
	"crypto"
	"encoding/json"
	"fmt"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
)

// CreateParams describes one JARM response to create.
type CreateParams struct {
	// Signer produces the response's signature.
	Signer crypto.Signer

	// Algorithm the response is signed with. Signer's key must match it.
	Algorithm fapi.SignatureAlgorithm

	// KeyID, if non-empty, is recorded in the response's "kid" header so
	// the verifier can select the right key from the server's published
	// JWKS without trial and error.
	KeyID string

	// Issuer is the "iss" claim — the authorization server's issuer
	// identifier.
	Issuer string

	// Audience is the "aud" claim — the client ID this response is
	// intended for.
	Audience string

	// Now is the response's issuance time.
	Now time.Time

	// Lifetime bounds how long the response is valid for (exp = Now +
	// Lifetime). JARM responses are meant to be consumed immediately, so
	// this should be short.
	Lifetime time.Duration

	// Parameters are the authorization response parameters to embed as
	// top-level claims — code and state for a success response, or
	// error, error_description and error_uri (plus state) for an error
	// response — each already encoded as JSON. Parameters must not use
	// the JWT-standard claim names iss, aud, exp, nbf or iat; Create
	// sets those itself.
	Parameters map[string]json.RawMessage
}

// Create builds and signs a JARM response for p. Success and error
// responses are created identically — Create has no notion of which
// this is, since both must be signed and verified with the same rigor.
func Create(p CreateParams) (string, error) {
	if p.Signer == nil {
		return "", fmt.Errorf("jarm: signer is nil")
	}
	if !p.Algorithm.IsValid() {
		return "", fmt.Errorf("jarm: invalid algorithm %v", p.Algorithm)
	}
	if p.Issuer == "" {
		return "", fmt.Errorf("jarm: issuer is empty")
	}
	if p.Audience == "" {
		return "", fmt.Errorf("jarm: audience is empty")
	}
	if p.Now.IsZero() {
		return "", fmt.Errorf("jarm: now is zero")
	}
	if p.Lifetime <= 0 {
		return "", fmt.Errorf("jarm: lifetime must be positive")
	}
	for _, reserved := range []string{"iss", "aud", "exp", "nbf", "iat"} {
		if _, ok := p.Parameters[reserved]; ok {
			return "", fmt.Errorf("jarm: parameters must not set reserved claim %q", reserved)
		}
	}

	claims := make(map[string]json.RawMessage, len(p.Parameters)+4)
	for k, v := range p.Parameters {
		claims[k] = v
	}
	standard := map[string]any{
		"iss": p.Issuer,
		"aud": p.Audience,
		"exp": p.Now.Add(p.Lifetime).Unix(),
		"iat": p.Now.Unix(),
	}
	for k, v := range standard {
		encoded, err := json.Marshal(v)
		if err != nil {
			return "", fmt.Errorf("jarm: marshal %q: %w", k, err)
		}
		claims[k] = encoded
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("jarm: marshal claims: %w", err)
	}

	header := jose.Header{Algorithm: p.Algorithm, KeyID: p.KeyID}
	token, err := jose.Sign(p.Signer, header, payload)
	if err != nil {
		return "", fmt.Errorf("jarm: %w", err)
	}
	return token, nil
}

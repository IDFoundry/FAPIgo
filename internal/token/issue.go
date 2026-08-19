package token

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
)

// jtiSize is the byte length of the random value used to build an
// access token's "jti" claim — 128 bits.
const jtiSize = 16

var accessTokenReservedClaims = []string{"iss", "sub", "aud", "client_id", "scope", "exp", "iat", "jti", "cnf"}

// AccessTokenParams describes one access token to issue.
type AccessTokenParams struct {
	Signer    crypto.Signer
	Algorithm fapi.SignatureAlgorithm
	KeyID     string

	Issuer   string
	Subject  string
	Audience string
	ClientID string
	Scope    string // "" to omit

	// Confirmation binds the token to a DPoP key by thumbprint. Leave
	// nil to issue a bearer (non-sender-constrained) token — whether
	// that's acceptable is a policy decision made above this package.
	Confirmation *Confirmation

	Now      time.Time
	Lifetime time.Duration

	// Random is the source of randomness for the token's "jti". If nil,
	// crypto/rand.Reader is used.
	Random io.Reader

	// Parameters are additional top-level claims to embed — most
	// notably a granted authorization_details (RFC 9396) — each already
	// encoded as JSON. Parameters must not use the reserved claim names
	// this package manages itself.
	Parameters map[string]json.RawMessage
}

// IssueAccessToken builds and signs a JWT access token for p, returning
// the compact JWT and the "jti" claim embedded in it — callers that
// need to later revoke this specific token (e.g. on detected
// authorization-code reuse, RFC 6749 §4.1.2) need the jti; previously
// generated internally and discarded.
func IssueAccessToken(p AccessTokenParams) (token string, jti string, err error) {
	if p.Signer == nil {
		return "", "", fmt.Errorf("token: signer is nil")
	}
	if !p.Algorithm.IsValid() {
		return "", "", fmt.Errorf("token: invalid algorithm %v", p.Algorithm)
	}
	if p.Issuer == "" {
		return "", "", fmt.Errorf("token: issuer is empty")
	}
	if p.Subject == "" {
		return "", "", fmt.Errorf("token: subject is empty")
	}
	if p.Audience == "" {
		return "", "", fmt.Errorf("token: audience is empty")
	}
	if p.ClientID == "" {
		return "", "", fmt.Errorf("token: client ID is empty")
	}
	if p.Now.IsZero() {
		return "", "", fmt.Errorf("token: now is zero")
	}
	if p.Lifetime <= 0 {
		return "", "", fmt.Errorf("token: lifetime must be positive")
	}
	for _, reserved := range accessTokenReservedClaims {
		if _, ok := p.Parameters[reserved]; ok {
			return "", "", fmt.Errorf("token: parameters must not set reserved claim %q", reserved)
		}
	}
	if p.Confirmation != nil && p.Confirmation.JKT == "" {
		return "", "", fmt.Errorf("token: confirmation jkt is empty")
	}

	jti, err = randomJTI(p.Random)
	if err != nil {
		return "", "", fmt.Errorf("token: generate jti: %w", err)
	}

	claims := make(map[string]json.RawMessage, len(p.Parameters)+8)
	for k, v := range p.Parameters {
		claims[k] = v
	}
	standard := map[string]any{
		"iss":       p.Issuer,
		"sub":       p.Subject,
		"aud":       p.Audience,
		"client_id": p.ClientID,
		"exp":       p.Now.Add(p.Lifetime).Unix(),
		"iat":       p.Now.Unix(),
		"jti":       jti,
	}
	if p.Scope != "" {
		standard["scope"] = p.Scope
	}
	if p.Confirmation != nil {
		standard["cnf"] = rawConfirmation{JKT: p.Confirmation.JKT}
	}
	for k, v := range standard {
		encoded, err := json.Marshal(v)
		if err != nil {
			return "", "", fmt.Errorf("token: marshal %q: %w", k, err)
		}
		claims[k] = encoded
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", "", fmt.Errorf("token: marshal claims: %w", err)
	}

	header := jose.Header{Algorithm: p.Algorithm, Type: atJWTType, KeyID: p.KeyID}
	tok, err := jose.Sign(p.Signer, header, payload)
	if err != nil {
		return "", "", fmt.Errorf("token: %w", err)
	}
	return tok, jti, nil
}

var idTokenReservedClaims = []string{"iss", "sub", "aud", "exp", "iat", "nonce", "auth_time", "acr", "amr"}

// IDTokenParams describes one ID token to issue.
type IDTokenParams struct {
	Signer    crypto.Signer
	Algorithm fapi.SignatureAlgorithm
	KeyID     string

	Issuer   string
	Subject  string
	Audience string

	Nonce    string    // "" to omit
	AuthTime time.Time // zero to omit
	ACR      string    // "" to omit
	AMR      []string  // nil to omit

	Now      time.Time
	Lifetime time.Duration

	// Parameters are additional top-level claims to embed, each already
	// encoded as JSON. Parameters must not use the reserved claim names
	// this package manages itself.
	Parameters map[string]json.RawMessage
}

// IssueIDToken builds and signs an ID token for p.
func IssueIDToken(p IDTokenParams) (string, error) {
	if p.Signer == nil {
		return "", fmt.Errorf("token: signer is nil")
	}
	if !p.Algorithm.IsValid() {
		return "", fmt.Errorf("token: invalid algorithm %v", p.Algorithm)
	}
	if p.Issuer == "" {
		return "", fmt.Errorf("token: issuer is empty")
	}
	if p.Subject == "" {
		return "", fmt.Errorf("token: subject is empty")
	}
	if p.Audience == "" {
		return "", fmt.Errorf("token: audience is empty")
	}
	if p.Now.IsZero() {
		return "", fmt.Errorf("token: now is zero")
	}
	if p.Lifetime <= 0 {
		return "", fmt.Errorf("token: lifetime must be positive")
	}
	for _, reserved := range idTokenReservedClaims {
		if _, ok := p.Parameters[reserved]; ok {
			return "", fmt.Errorf("token: parameters must not set reserved claim %q", reserved)
		}
	}

	claims := make(map[string]json.RawMessage, len(p.Parameters)+8)
	for k, v := range p.Parameters {
		claims[k] = v
	}
	standard := map[string]any{
		"iss": p.Issuer,
		"sub": p.Subject,
		"aud": p.Audience,
		"exp": p.Now.Add(p.Lifetime).Unix(),
		"iat": p.Now.Unix(),
	}
	if p.Nonce != "" {
		standard["nonce"] = p.Nonce
	}
	if !p.AuthTime.IsZero() {
		standard["auth_time"] = p.AuthTime.Unix()
	}
	if p.ACR != "" {
		standard["acr"] = p.ACR
	}
	if len(p.AMR) > 0 {
		standard["amr"] = p.AMR
	}
	for k, v := range standard {
		encoded, err := json.Marshal(v)
		if err != nil {
			return "", fmt.Errorf("token: marshal %q: %w", k, err)
		}
		claims[k] = encoded
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("token: marshal claims: %w", err)
	}

	header := jose.Header{Algorithm: p.Algorithm, KeyID: p.KeyID}
	tok, err := jose.Sign(p.Signer, header, payload)
	if err != nil {
		return "", fmt.Errorf("token: %w", err)
	}
	return tok, nil
}

func randomJTI(r io.Reader) (string, error) {
	if r == nil {
		r = rand.Reader
	}
	buf := make([]byte, jtiSize)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

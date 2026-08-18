package requestobject

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
// object's "jti" claim — 128 bits.
const jtiSize = 16

// CreateParams describes one request object to create.
type CreateParams struct {
	// Signer produces the object's signature.
	Signer crypto.Signer

	// Algorithm the object is signed with. Signer's key must match it.
	Algorithm fapi.SignatureAlgorithm

	// KeyID, if non-empty, is recorded in the object's "kid" header so
	// the verifier can select the right key from this client's
	// registered JWKS without trial and error.
	KeyID string

	// ClientID is the "iss" claim (RFC 9101 §5.3). If Parameters
	// contains a "client_id" entry, it must equal ClientID exactly.
	ClientID string

	// Audience is the "aud" claim — the authorization server issuer
	// identifier this object is scoped to.
	Audience string

	// Now is the object's issuance time.
	Now time.Time

	// Lifetime bounds how long the object is valid for (exp = Now +
	// Lifetime). FAPI profiles expect this to be short.
	Lifetime time.Duration

	// Random is the source of randomness for the object's "jti". If
	// nil, crypto/rand.Reader is used.
	Random io.Reader

	// Parameters are the authorization request parameters to embed as
	// top-level claims — response_type, client_id, redirect_uri, scope,
	// state, nonce, code_challenge, code_challenge_method,
	// authorization_details, and any registered extension parameter —
	// each already encoded as JSON. Parameters must not use the
	// JWT-standard claim names iss, aud, exp, nbf, iat or jti; Create
	// sets those itself.
	Parameters map[string]json.RawMessage
}

// Create builds and signs a request object for p.
func Create(p CreateParams) (string, error) {
	if p.Signer == nil {
		return "", fmt.Errorf("requestobject: signer is nil")
	}
	if !p.Algorithm.IsValid() {
		return "", fmt.Errorf("requestobject: invalid algorithm %v", p.Algorithm)
	}
	if p.ClientID == "" {
		return "", fmt.Errorf("requestobject: client ID is empty")
	}
	if p.Audience == "" {
		return "", fmt.Errorf("requestobject: audience is empty")
	}
	if p.Now.IsZero() {
		return "", fmt.Errorf("requestobject: now is zero")
	}
	if p.Lifetime <= 0 {
		return "", fmt.Errorf("requestobject: lifetime must be positive")
	}
	for _, reserved := range []string{"iss", "aud", "exp", "nbf", "iat", "jti"} {
		if _, ok := p.Parameters[reserved]; ok {
			return "", fmt.Errorf("requestobject: parameters must not set reserved claim %q", reserved)
		}
	}
	if clientIDRaw, ok := p.Parameters["client_id"]; ok {
		var clientID string
		if err := json.Unmarshal(clientIDRaw, &clientID); err != nil || clientID != p.ClientID {
			return "", fmt.Errorf("requestobject: parameters[\"client_id\"] must equal ClientID")
		}
	}

	jti, err := randomJTI(p.Random)
	if err != nil {
		return "", fmt.Errorf("requestobject: generate jti: %w", err)
	}

	claims := make(map[string]json.RawMessage, len(p.Parameters)+6)
	for k, v := range p.Parameters {
		claims[k] = v
	}
	standard := map[string]any{
		"iss": p.ClientID,
		"aud": p.Audience,
		"exp": p.Now.Add(p.Lifetime).Unix(),
		"nbf": p.Now.Unix(),
		"iat": p.Now.Unix(),
		"jti": jti,
	}
	for k, v := range standard {
		encoded, err := json.Marshal(v)
		if err != nil {
			return "", fmt.Errorf("requestobject: marshal %q: %w", k, err)
		}
		claims[k] = encoded
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("requestobject: marshal claims: %w", err)
	}

	header := jose.Header{Algorithm: p.Algorithm, Type: jwtType, KeyID: p.KeyID}
	token, err := jose.Sign(p.Signer, header, payload)
	if err != nil {
		return "", fmt.Errorf("requestobject: %w", err)
	}
	return token, nil
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

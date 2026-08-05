package clientassertion

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"

	fapi "github.com/osanderson/go-fapi"
	"github.com/osanderson/go-fapi/internal/jose"
)

// jtiSize is the byte length of the random value used to build an
// assertion's "jti" claim — 128 bits.
const jtiSize = 16

// AssertionRequest describes one client assertion to create.
type AssertionRequest struct {
	// Signer produces the assertion's signature.
	Signer crypto.Signer

	// Algorithm the assertion is signed with. Signer's key must match
	// it.
	Algorithm fapi.SignatureAlgorithm

	// KeyID, if non-empty, is recorded in the assertion's "kid" header
	// so the verifier can select the right key from this client's
	// registered JWKS without trial and error.
	KeyID string

	// ClientID is used as both the "iss" and "sub" claims, per RFC 7523
	// §3.
	ClientID string

	// Audience is the "aud" claim — the authorization server's token or
	// PAR endpoint URL that this assertion is scoped to.
	Audience string

	// Now is the assertion's issuance time.
	Now time.Time

	// Lifetime bounds how long the assertion is valid for (exp = Now +
	// Lifetime). Callers should keep this short — a client assertion is
	// a bearer credential for as long as it remains unexpired and
	// unused.
	Lifetime time.Duration

	// Random is the source of randomness for the assertion's "jti". If
	// nil, crypto/rand.Reader is used.
	Random io.Reader
}

// CreateAssertion builds and signs a client assertion JWT for req.
func CreateAssertion(req AssertionRequest) (string, error) {
	if req.Signer == nil {
		return "", fmt.Errorf("clientassertion: signer is nil")
	}
	if !req.Algorithm.IsValid() {
		return "", fmt.Errorf("clientassertion: invalid algorithm %v", req.Algorithm)
	}
	if req.ClientID == "" {
		return "", fmt.Errorf("clientassertion: client ID is empty")
	}
	if req.Audience == "" {
		return "", fmt.Errorf("clientassertion: audience is empty")
	}
	if req.Now.IsZero() {
		return "", fmt.Errorf("clientassertion: now is zero")
	}
	if req.Lifetime <= 0 {
		return "", fmt.Errorf("clientassertion: lifetime must be positive")
	}

	jti, err := randomJTI(req.Random)
	if err != nil {
		return "", fmt.Errorf("clientassertion: generate jti: %w", err)
	}

	c := claims{
		Issuer:    req.ClientID,
		Subject:   req.ClientID,
		Audience:  req.Audience,
		JTI:       jti,
		IssuedAt:  req.Now.Unix(),
		ExpiresAt: req.Now.Add(req.Lifetime).Unix(),
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("clientassertion: marshal claims: %w", err)
	}

	header := jose.Header{Algorithm: req.Algorithm, KeyID: req.KeyID}
	assertion, err := jose.Sign(req.Signer, header, payload)
	if err != nil {
		return "", fmt.Errorf("clientassertion: %w", err)
	}
	return assertion, nil
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

package clientattestation

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

// jtiSize is the byte length of the random value used to build a PoP's
// "jti" claim — 128 bits, matching clientassertion's own convention.
const jtiSize = 16

// PoPCreateRequest describes one Client Attestation PoP JWT to create
// (draft-07 §5.2). The accompanying Client Attestation JWT itself is
// never built by this package — it's an opaque, pre-issued, reusable
// credential obtained out of band from an Attester (§10.2); only the
// PoP is freshly built and signed per request.
type PoPCreateRequest struct {
	// Signer produces the PoP's signature — the Client Instance Key,
	// the private half of whatever public JWK the accompanying Client
	// Attestation JWT names in its own "cnf.jwk" claim. This package
	// does not check that correspondence itself; the caller is
	// responsible for signing with the right key.
	Signer crypto.Signer

	// Algorithm the PoP is signed with. Signer's key must match it.
	Algorithm fapi.SignatureAlgorithm

	// ClientID is the "iss" claim — must equal the accompanying Client
	// Attestation JWT's own "sub" claim (draft-07 §9 rule 13).
	ClientID fapi.ClientID

	// Audience is the "aud" claim — the authorization server's own RFC
	// 8414 issuer identifier. draft-07 grants this JWT no endpoint-URL
	// carve-out the way RFC 7523 grants a client assertion (see
	// PoPVerifyPolicy.ExpectedAudience's own doc comment).
	Audience string

	// Now is the PoP's issuance time (its "iat" claim) — the PoP's own
	// freshness anchor; it carries no "exp" claim of its own (see
	// PoPVerifyPolicy.MaxAge's own doc comment for how a verifier
	// bounds it instead).
	Now time.Time

	// Random is the source of randomness for the PoP's "jti". If nil,
	// crypto/rand.Reader is used.
	Random io.Reader
}

// CreatePoP builds and signs a Client Attestation PoP JWT for req.
func CreatePoP(req PoPCreateRequest) (string, error) {
	if req.Signer == nil {
		return "", fmt.Errorf("clientattestation: signer is nil")
	}
	if !req.Algorithm.IsValid() {
		return "", fmt.Errorf("clientattestation: invalid algorithm %v", req.Algorithm)
	}
	if req.ClientID == "" {
		return "", fmt.Errorf("clientattestation: client ID is empty")
	}
	if req.Audience == "" {
		return "", fmt.Errorf("clientattestation: audience is empty")
	}
	if req.Now.IsZero() {
		return "", fmt.Errorf("clientattestation: now is zero")
	}

	jti, err := randomJTI(req.Random)
	if err != nil {
		return "", fmt.Errorf("clientattestation: generate jti: %w", err)
	}

	c := popClaims{
		Issuer:   string(req.ClientID),
		Audience: req.Audience,
		JTI:      jti,
		IssuedAt: req.Now.Unix(),
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("clientattestation: marshal claims: %w", err)
	}

	header := jose.Header{Algorithm: req.Algorithm, Type: PoPTypHeader}
	pop, err := jose.Sign(req.Signer, header, payload)
	if err != nil {
		return "", fmt.Errorf("clientattestation: %w", err)
	}
	return pop, nil
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

package dpop

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/canonical"
	"github.com/idfoundry/fapigo/internal/jose"
)

// jtiSize is the byte length of the random value used to build a proof's
// "jti" claim — 128 bits, in line with RFC 9449's recommendation.
const jtiSize = 16

// ProofRequest describes one DPoP proof to create.
type ProofRequest struct {
	// Signer produces the proof's signature. Its public key is embedded
	// in the proof header as the "jwk" member.
	Signer crypto.Signer

	// Algorithm the proof is signed with. Signer's key must match it.
	Algorithm fapi.SignatureAlgorithm

	// Method is the HTTP method of the request this proof is bound to.
	Method string

	// URL is the target URI of the request this proof is bound to. It is
	// canonicalized into the "htu" claim; query and fragment are
	// stripped per RFC 9449 §4.2.
	URL *url.URL

	// AccessToken, if non-empty, is hashed into the proof's "ath" claim
	// (RFC 9449 §4.3). Leave empty when creating a proof for a token
	// request, where no access token exists yet.
	AccessToken string

	// Nonce, if non-empty, is echoed into the proof's "nonce" claim in
	// response to a server-provided DPoP-Nonce challenge.
	Nonce string

	// Now is the proof's issuance time.
	Now time.Time

	// Random is the source of randomness for the proof's "jti". If nil,
	// crypto/rand.Reader is used.
	Random io.Reader
}

// CreateProof builds and signs a DPoP proof JWT for req.
func CreateProof(req ProofRequest) (string, error) {
	if req.Signer == nil {
		return "", fmt.Errorf("dpop: signer is nil")
	}
	if !req.Algorithm.IsValid() {
		return "", fmt.Errorf("dpop: invalid algorithm %v", req.Algorithm)
	}
	if req.Method == "" {
		return "", fmt.Errorf("dpop: method is empty")
	}
	if req.URL == nil {
		return "", fmt.Errorf("dpop: url is nil")
	}
	if req.Now.IsZero() {
		return "", fmt.Errorf("dpop: now is zero")
	}

	jwk, err := jose.NewJWK(req.Signer.Public(), req.Algorithm)
	if err != nil {
		return "", fmt.Errorf("dpop: %w", err)
	}

	jti, err := randomJTI(req.Random)
	if err != nil {
		return "", fmt.Errorf("dpop: generate jti: %w", err)
	}

	c := claims{
		JTI: jti,
		HTM: strings.ToUpper(req.Method),
		HTU: canonical.URI(req.URL),
		IAT: req.Now.Unix(),
	}
	if req.AccessToken != "" {
		c.ATH = accessTokenHash(req.AccessToken)
	}
	if req.Nonce != "" {
		c.Nonce = req.Nonce
	}

	payload, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("dpop: marshal claims: %w", err)
	}

	header := jose.Header{Algorithm: req.Algorithm, Type: jwtType, JWK: &jwk}
	proof, err := jose.Sign(req.Signer, header, payload)
	if err != nil {
		return "", fmt.Errorf("dpop: %w", err)
	}
	return proof, nil
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

func accessTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

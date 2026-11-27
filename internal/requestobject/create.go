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
	"github.com/idfoundry/fapigo/internal/strictjson"
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

	// ClientID is the "iss" claim. If Parameters
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
	// JWT-standard claim names iss, aud, exp, nbf, iat or jti, which
	// Create sets itself, or sub, which Verify refuses in a request
	// object. A value repeating a member with differing copies, or as a
	// case variant, and a name that is a case variant of another
	// parameter or of one of those claims, are refused, as Verify would
	// refuse the object.
	Parameters map[string]json.RawMessage
}

// Create builds and signs a request object for p.
func Create(p CreateParams) (string, error) {
	if err := validateCreateParams(p); err != nil {
		return "", err
	}

	jti, err := randomJTI(p.Random)
	if err != nil {
		return "", fmt.Errorf("requestobject: generate jti: %w", err)
	}

	claims, err := createClaims(p, jti)
	if err != nil {
		return "", err
	}

	// Without HTML escaping: json.Marshal would escape <, > and & in
	// every json.RawMessage parameter too, so authorization_details the
	// server keeps byte for byte would arrive as \u003c and so on.
	payload, err := strictjson.MarshalUnescaped(claims)
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

// validateCreateParams checks p's required fields and the claims its
// Parameters must not set, split out of Create to keep its cognitive
// complexity manageable.
func validateCreateParams(p CreateParams) error {
	if p.Signer == nil {
		return fmt.Errorf("requestobject: signer is nil")
	}
	if !p.Algorithm.IsValid() {
		return fmt.Errorf("requestobject: invalid algorithm %v", p.Algorithm)
	}
	if p.ClientID == "" {
		return fmt.Errorf("requestobject: client ID is empty")
	}
	if p.Audience == "" {
		return fmt.Errorf("requestobject: audience is empty")
	}
	if p.Now.IsZero() {
		return fmt.Errorf("requestobject: now is zero")
	}
	if p.Lifetime <= 0 {
		return fmt.Errorf("requestobject: lifetime must be positive")
	}
	// "sub" is refused as Verify refuses it: it's the claim a client
	// assertion authenticates by (RFC 7523 §3), and a request object
	// carrying it could be presented as one (see ErrUnexpectedSubject).
	for _, reserved := range []string{"iss", "aud", "exp", "nbf", "iat", "jti", "sub"} {
		if _, ok := p.Parameters[reserved]; ok {
			return fmt.Errorf("requestobject: parameters must not set reserved claim %q", reserved)
		}
	}
	if clientIDRaw, ok := p.Parameters["client_id"]; ok {
		var clientID string
		if err := json.Unmarshal(clientIDRaw, &clientID); err != nil || clientID != p.ClientID {
			return fmt.Errorf("requestobject: parameters[\"client_id\"] must equal ClientID")
		}
	}
	return nil
}

// createClaims is the request object's claims set: p.Parameters and
// the claims Create sets, refused if Verify would refuse it.
func createClaims(p CreateParams, jti string) (map[string]json.RawMessage, error) {
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
			return nil, fmt.Errorf("requestobject: marshal %q: %w", k, err)
		}
		claims[k] = encoded
	}
	// Verify refuses a request object repeating a member with differing
	// copies, or as a case variant, at any depth: readers keeping the
	// first copy and the last would take different requests from it.
	// So is a parameter spelled as a case variant of another, or of a
	// claim set here ("ISS", say).
	if name, err := strictjson.CheckConflictingObject(claims); err != nil {
		return nil, fmt.Errorf("requestobject: parameter %q would not parse: %w", name, err)
	}
	return claims, nil
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

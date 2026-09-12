package federation

import (
	"crypto"
	"encoding/json"
	"fmt"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
)

// trustMarkStatusResponseJWTType is the JWS "typ" header value every
// Trust Mark Status Response JWT MUST carry (OpenID Federation 1.0
// §8: "explicitly typed by setting the typ header parameter to
// trust-mark-status-response+jwt").
const trustMarkStatusResponseJWTType = "trust-mark-status-response+jwt"

// TrustMarkStatus is the "status" claim of a Trust Mark Status
// Response (OpenID Federation 1.0 §8) — a defined string type rather
// than a closed Go enum, since the spec explicitly allows more values
// than the four it defines ("Additional status values MAY be defined
// and used in addition to those above").
type TrustMarkStatus string

const (
	// TrustMarkStatusActive indicates the Trust Mark is active.
	TrustMarkStatusActive TrustMarkStatus = "active"

	// TrustMarkStatusExpired indicates the Trust Mark has expired.
	TrustMarkStatusExpired TrustMarkStatus = "expired"

	// TrustMarkStatusRevoked indicates the Trust Mark was revoked.
	TrustMarkStatusRevoked TrustMarkStatus = "revoked"

	// TrustMarkStatusInvalid indicates signature validation failed or
	// another error was detected.
	TrustMarkStatusInvalid TrustMarkStatus = "invalid"
)

// TrustMarkStatusResponseClaims is a parsed Trust Mark Status Response
// JWT payload (OpenID Federation 1.0 §8).
type TrustMarkStatusResponseClaims struct {
	Issuer    string
	IssuedAt  time.Time
	TrustMark string
	Status    TrustMarkStatus
}

// TrustMarkStatusResponse is a parsed, but not yet signature-verified,
// Trust Mark Status Response JWT — the same "claims safe to read as
// lookup keys, never as a basis for trust until Verify succeeds"
// contract TrustMark and TrustMarkDelegation already establish.
type TrustMarkStatusResponse struct {
	compact jose.Compact
	claims  TrustMarkStatusResponseClaims
}

// ParseTrustMarkStatusResponse parses token without verifying its
// signature.
func ParseTrustMarkStatusResponse(token string) (TrustMarkStatusResponse, error) {
	compact, err := jose.ParseCompact(token)
	if err != nil {
		return TrustMarkStatusResponse{}, fmt.Errorf("federation: %w", err)
	}
	if compact.Header.Type != trustMarkStatusResponseJWTType {
		return TrustMarkStatusResponse{}, ErrTrustMarkStatusResponseWrongType
	}
	claims, err := parseTrustMarkStatusResponseClaims(compact.Payload)
	if err != nil {
		return TrustMarkStatusResponse{}, err
	}
	return TrustMarkStatusResponse{compact: compact, claims: claims}, nil
}

// KeyID returns the response header's "kid", or "" if absent.
// Untrusted until Verify succeeds; use only to select which of the
// issuer's published keys to verify against.
func (r TrustMarkStatusResponse) KeyID() string { return r.compact.Header.KeyID }

// Algorithm returns the algorithm the response header claims to use.
// Untrusted until Verify succeeds — a caller must still supply the
// algorithm it expects via TrustMarkStatusResponseVerifyPolicy rather
// than trusting this value, exactly as jose.Compact.Verify requires.
func (r TrustMarkStatusResponse) Algorithm() fapi.SignatureAlgorithm {
	return r.compact.Header.Algorithm
}

// ClaimedIssuer returns the response's unverified "iss" claim.
func (r TrustMarkStatusResponse) ClaimedIssuer() string { return r.claims.Issuer }

// ClaimedTrustMark returns the response's unverified "trust_mark"
// claim, for use as a lookup key only.
func (r TrustMarkStatusResponse) ClaimedTrustMark() string { return r.claims.TrustMark }

// TrustMarkStatusResponseVerifyPolicy is the set of checks Verify
// enforces against a TrustMarkStatusResponse.
type TrustMarkStatusResponseVerifyPolicy struct {
	// ExpectedIssuer is the Trust Mark Issuer the caller queried — the
	// response's iss claim must equal it exactly. §8: "The query MUST
	// be sent to the Trust Mark Issuer," so the entity answering is
	// always known before the response is ever parsed.
	ExpectedIssuer string

	// ExpectedTrustMark is the Trust Mark the caller actually queried
	// about — the response's trust_mark claim must equal it exactly
	// (see ErrTrustMarkStatusResponseTrustMarkMismatch's own doc
	// comment for why).
	ExpectedTrustMark string

	// Algorithm is the algorithm the Trust Mark Issuer is registered or
	// discovered to sign with. The response header's algorithm must
	// equal it exactly — this is what prevents algorithm-confusion
	// attacks, so it must come from the issuer's own published jwks
	// (via its kid), never trusted from the response itself.
	Algorithm fapi.SignatureAlgorithm

	// Now is the time to validate iat against. There is no exp claim to
	// also check — §8 defines no expiry for a Trust Mark Status
	// Response itself; it's a point-in-time answer, not a credential
	// with its own validity window.
	Now time.Time

	// MaxClockSkew bounds how far in the future an iat claim may be.
	// Zero means no tolerance.
	MaxClockSkew time.Duration
}

// Verify checks r's signature against pub and its claims against
// policy, returning the response's now-trusted claims.
func (r TrustMarkStatusResponse) Verify(pub crypto.PublicKey, policy TrustMarkStatusResponseVerifyPolicy) (TrustMarkStatusResponseClaims, error) {
	if policy.ExpectedIssuer == "" {
		return TrustMarkStatusResponseClaims{}, fmt.Errorf("federation: ExpectedIssuer is empty")
	}
	if policy.ExpectedTrustMark == "" {
		return TrustMarkStatusResponseClaims{}, fmt.Errorf("federation: ExpectedTrustMark is empty")
	}
	if policy.Now.IsZero() {
		return TrustMarkStatusResponseClaims{}, fmt.Errorf("federation: Now is zero")
	}

	if err := r.compact.Verify(pub, policy.Algorithm); err != nil {
		return TrustMarkStatusResponseClaims{}, fmt.Errorf("federation: %w", err)
	}
	c := r.claims

	if c.Issuer != policy.ExpectedIssuer {
		return TrustMarkStatusResponseClaims{}, ErrTrustMarkStatusResponseIssuerMismatch
	}
	if c.TrustMark != policy.ExpectedTrustMark {
		return TrustMarkStatusResponseClaims{}, ErrTrustMarkStatusResponseTrustMarkMismatch
	}
	if policy.Now.Before(c.IssuedAt.Add(-policy.MaxClockSkew)) {
		return TrustMarkStatusResponseClaims{}, ErrTrustMarkStatusResponseNotYetValid
	}

	return c, nil
}

func parseTrustMarkStatusResponseClaims(payload []byte) (TrustMarkStatusResponseClaims, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil {
		return TrustMarkStatusResponseClaims{}, fmt.Errorf("%w: %v", ErrMalformedClaims, err)
	}

	iss, err := popRequiredString(raw, "iss")
	if err != nil {
		return TrustMarkStatusResponseClaims{}, err
	}
	trustMark, err := popRequiredString(raw, "trust_mark")
	if err != nil {
		return TrustMarkStatusResponseClaims{}, err
	}
	status, err := popRequiredString(raw, "status")
	if err != nil {
		return TrustMarkStatusResponseClaims{}, err
	}
	iat, err := popRequiredInt64(raw, "iat")
	if err != nil {
		return TrustMarkStatusResponseClaims{}, err
	}

	return TrustMarkStatusResponseClaims{
		Issuer: iss, TrustMark: trustMark, Status: TrustMarkStatus(status),
		IssuedAt: time.Unix(iat, 0),
	}, nil
}

// CreateTrustMarkStatusResponseParams describes one Trust Mark Status
// Response to create (OpenID Federation 1.0 §8).
type CreateTrustMarkStatusResponseParams struct {
	// Signer produces the response's signature — the Trust Mark
	// Issuer's own federation key (the same one that signed the Trust
	// Mark itself, or, if it was issued under a delegation, the
	// delegate's own key).
	Signer crypto.Signer

	// Algorithm Signer signs with.
	Algorithm fapi.SignatureAlgorithm

	// KeyID is recorded in the response's "kid" header. Required —
	// OpenID Federation 1.0 §8: "The Trust Mark Status Response JWT
	// MUST include the kid header parameter."
	KeyID string

	// Issuer is the "iss" claim — the Trust Mark Issuer answering the
	// query, i.e. this same entity.
	Issuer string

	// TrustMark is the "trust_mark" claim — the exact Trust Mark JWT
	// this response is about.
	TrustMark string

	// Status is the "status" claim.
	Status TrustMarkStatus

	// Now is the response's issuance time ("iat").
	Now time.Time
}

// CreateTrustMarkStatusResponse builds and signs a Trust Mark Status
// Response JWT for p.
func CreateTrustMarkStatusResponse(p CreateTrustMarkStatusResponseParams) (string, error) {
	if p.Signer == nil {
		return "", fmt.Errorf("federation: signer is nil")
	}
	if !p.Algorithm.IsValid() {
		return "", fmt.Errorf("federation: invalid algorithm %v", p.Algorithm)
	}
	if p.KeyID == "" {
		return "", fmt.Errorf(`federation: key id is required (OpenID Federation 1.0 §8: "The Trust Mark Status Response JWT MUST include the kid header parameter")`)
	}
	if p.Issuer == "" {
		return "", fmt.Errorf("federation: issuer is empty")
	}
	if p.TrustMark == "" {
		return "", fmt.Errorf("federation: trust mark is empty")
	}
	if p.Status == "" {
		return "", fmt.Errorf("federation: status is empty")
	}
	if p.Now.IsZero() {
		return "", fmt.Errorf("federation: now is zero")
	}

	claims := map[string]any{
		"iss": p.Issuer, "iat": p.Now.Unix(), "trust_mark": p.TrustMark, "status": string(p.Status),
	}
	return signClaims(p.Signer, p.Algorithm, p.KeyID, trustMarkStatusResponseJWTType, claims)
}

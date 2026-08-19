package resource

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/token"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/storage"
)

// VerifyAccessTokenRequest is the input to
// AccessTokenVerifier.VerifyAccessToken.
type VerifyAccessTokenRequest struct {
	// Raw is the presented access token, exactly as received.
	Raw string

	// Thumbprint is the caller's already-verified DPoP proof key
	// thumbprint — the presented token must be sender-constrained to
	// it.
	Thumbprint string

	Now          time.Time
	MaxClockSkew time.Duration
}

// ValidatedAccessToken is what a successful VerifyAccessToken returns.
type ValidatedAccessToken struct {
	Subject   string
	ClientID  string
	Scopes    []string
	Claims    map[string]json.RawMessage
	ExpiresAt time.Time

	// Key is this token's revocation-lookup identifier — a JWT's jti
	// claim for JWTAccessTokens, an opaque token's own hash for
	// OpaqueAccessTokens — passed to Dependencies.Revocation.IsRevoked
	// exactly as returned; its shape is an implementation detail
	// specific to each AccessTokenVerifier.
	Key string
}

// AccessTokenVerifier checks a presented access token's structure/
// signature/lifetime and its DPoP sender-constraint binding — NOT
// revocation status, which Verify() checks separately and uniformly
// via Dependencies.Revocation regardless of format. Required — pass
// JWTAccessTokens{...} (the default), OpaqueAccessTokens{...}, or your
// own.
//
// A returned error should be a *Error (via this package's own
// newError, unexported but reachable from another file in this
// package) rather than a bare error — see ARCHITECTURE.md design rule
// 16, "Errors carry their own exposure": whether a failure is a
// client-facing invalid_token (401) or an operational server_error
// (500, e.g. IssuerKeys unreachable) is a distinction each
// AccessTokenVerifier implementation is best placed to make, not
// something Verify() should collapse into one status for every
// failure reason. Verify() propagates a *Error unchanged; a bare error
// falls back to ErrorInvalidToken/401.
type AccessTokenVerifier interface {
	VerifyAccessToken(ctx context.Context, req VerifyAccessTokenRequest) (ValidatedAccessToken, error)
}

// JWTAccessTokens verifies self-contained JWT access tokens (RFC 9068)
// — the format this verifier has always accepted, still the default.
// Owns Issuer/Audience/Algorithm/MaxTokenLifetime and its own
// IssuerKeys source — none of which Config/Dependencies carry, since
// every one of them is a JWT-specific concern with no other use in
// this package.
type JWTAccessTokens struct {
	IssuerKeys       keys.IssuerKeySource
	Issuer           fapi.URL
	Audience         string
	Algorithm        fapi.SignatureAlgorithm
	MaxTokenLifetime time.Duration
}

// NewJWTAccessTokens validates every field and returns a
// JWTAccessTokens. Not required — a caller confident its values are
// already correct may use the JWTAccessTokens{...} literal directly —
// but mirrors this module's other validate-at-construction
// constructors for callers who want it.
func NewJWTAccessTokens(issuerKeys keys.IssuerKeySource, issuer fapi.URL, audience string, algorithm fapi.SignatureAlgorithm, maxTokenLifetime time.Duration) (JWTAccessTokens, error) {
	if issuerKeys == nil {
		return JWTAccessTokens{}, fmt.Errorf("resource: JWTAccessTokens: issuer keys is required")
	}
	if issuer.IsZero() {
		return JWTAccessTokens{}, fmt.Errorf("resource: JWTAccessTokens: issuer is required")
	}
	if audience == "" {
		return JWTAccessTokens{}, fmt.Errorf("resource: JWTAccessTokens: audience is required")
	}
	if !algorithm.IsValid() {
		return JWTAccessTokens{}, fmt.Errorf("resource: JWTAccessTokens: algorithm is invalid")
	}
	if maxTokenLifetime <= 0 {
		return JWTAccessTokens{}, fmt.Errorf("resource: JWTAccessTokens: max token lifetime must be positive")
	}
	return JWTAccessTokens{
		IssuerKeys: issuerKeys, Issuer: issuer, Audience: audience,
		Algorithm: algorithm, MaxTokenLifetime: maxTokenLifetime,
	}, nil
}

// VerifyAccessToken implements AccessTokenVerifier.
func (j JWTAccessTokens) VerifyAccessToken(ctx context.Context, req VerifyAccessTokenRequest) (ValidatedAccessToken, error) {
	parsed, err := token.ParseAccessToken(req.Raw)
	if err != nil {
		return ValidatedAccessToken{}, newError(ErrorInvalidToken, 401, "access token is malformed", err)
	}

	candidates, err := j.IssuerKeys.ResolveIssuerKeys(ctx, keys.IssuerKeyRequest{
		Issuer:    j.Issuer.String(),
		Purpose:   keys.AccessTokenVerification,
		Algorithm: j.Algorithm,
		KeyID:     parsed.KeyID(),
	})
	if err != nil {
		return ValidatedAccessToken{}, newError(ErrorServerError, 500, "failed to resolve issuer keys", err)
	}
	if len(candidates.Keys) == 0 {
		return ValidatedAccessToken{}, newError(ErrorInvalidToken, 401, "no matching issuer key", nil)
	}

	policy := token.AccessTokenValidatePolicy{
		ExpectedIssuer:     j.Issuer.String(),
		ExpectedAudience:   j.Audience,
		Algorithm:          j.Algorithm,
		ExpectedThumbprint: &req.Thumbprint,
		Now:                req.Now,
		MaxLifetime:        j.MaxTokenLifetime,
		MaxClockSkew:       req.MaxClockSkew,
	}

	var (
		validated token.ValidatedAccessToken
		validErr  error
	)
	// TODO: bound the number of candidates tried here if IssuerKeySource
	// ever becomes attacker-influenced (e.g. a live JWKS fetch keyed by
	// untrusted input) — an unbounded key set turns this loop into an
	// attacker-controlled amount of signature verification work.
	for _, candidate := range candidates.Keys {
		validated, validErr = parsed.Validate(candidate.PublicKey, policy)
		if validErr == nil {
			break
		}
	}
	if validErr != nil {
		return ValidatedAccessToken{}, newError(ErrorInvalidToken, 401, "access token is invalid", validErr)
	}

	var scopes []string
	if validated.Scope != "" {
		scopes = strings.Fields(validated.Scope)
	}
	return ValidatedAccessToken{
		Subject:   validated.Subject,
		ClientID:  validated.ClientID,
		Scopes:    scopes,
		Claims:    validated.Parameters,
		ExpiresAt: validated.ExpiresAt,
		// internal/token.ValidatedAccessToken.JTI is NOT renamed — it's
		// internal, JWT-only by construction (internal/token never
		// handles opaque tokens, see internal/token/doc.go). Only this
		// package-level ValidatedAccessToken.Key is.
		Key: validated.JTI,
	}, nil
}

// OpaqueAccessTokens verifies opaque, storage-backed access tokens:
// hash the presented token, look it up, check its DPoP thumbprint and
// expiry directly — there is no signature to verify.
type OpaqueAccessTokens struct {
	Store storage.AccessTokenStore
}

// NewOpaqueAccessTokens validates store is non-nil and returns an
// OpaqueAccessTokens.
func NewOpaqueAccessTokens(store storage.AccessTokenStore) (OpaqueAccessTokens, error) {
	if store == nil {
		return OpaqueAccessTokens{}, fmt.Errorf("resource: OpaqueAccessTokens: store is required")
	}
	return OpaqueAccessTokens{Store: store}, nil
}

// VerifyAccessToken implements AccessTokenVerifier.
func (o OpaqueAccessTokens) VerifyAccessToken(ctx context.Context, req VerifyAccessTokenRequest) (ValidatedAccessToken, error) {
	hash := sha256.Sum256([]byte(req.Raw))
	looked, err := o.Store.LookupAccessToken(ctx, storage.AccessTokenLookup{TokenHash: hash})
	if err != nil {
		return ValidatedAccessToken{}, newError(ErrorInvalidToken, 401, "access token is invalid", err)
	}
	if looked.Thumbprint != req.Thumbprint {
		return ValidatedAccessToken{}, newError(ErrorInvalidToken, 401, "access token is not bound to the presented DPoP key", nil)
	}
	if req.Now.After(looked.ExpiresAt.Add(req.MaxClockSkew)) {
		return ValidatedAccessToken{}, newError(ErrorInvalidToken, 401, "access token has expired", nil)
	}
	return ValidatedAccessToken{
		Subject:   looked.Subject,
		ClientID:  looked.ClientID.String(),
		Scopes:    looked.Scope,
		Claims:    looked.Claims,
		ExpiresAt: looked.ExpiresAt,
		Key:       hex.EncodeToString(hash[:]),
	}, nil
}

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

// ResolveAccessTokenRequest is the input to
// AccessTokenResolver.ResolveAccessToken.
type ResolveAccessTokenRequest struct {
	// Raw is the presented access token, exactly as received.
	Raw string

	// Now is available for a format-specific issuance-time sanity
	// check (e.g. JWTAccessTokens' defense against a forged/over-long
	// exp claim) — NOT for checking ordinary expiry, which Verify()
	// does uniformly for every implementation. See AccessTokenResolver's
	// own doc comment.
	Now time.Time
}

// ResolvedAccessToken is what a successful ResolveAccessToken returns.
type ResolvedAccessToken struct {
	Subject   string
	ClientID  string
	Scopes    []string
	Claims    map[string]json.RawMessage
	ExpiresAt time.Time

	// Thumbprint is this token's own claimed/stored DPoP-binding
	// thumbprint (e.g. a JWT's signature-verified cnf.jkt claim, or an
	// opaque token's stored thumbprint) — Verify() compares it against
	// the caller's already-verified DPoP proof; this method does not.
	Thumbprint string

	// Key is this token's revocation-lookup identifier — a JWT's jti
	// claim for JWTAccessTokens, an opaque token's own hash for
	// OpaqueAccessTokens — passed to Dependencies.Revocation.IsRevoked
	// exactly as returned; its shape is an implementation detail
	// specific to each AccessTokenResolver.
	Key string
}

// AccessTokenResolver resolves a presented access token's raw bytes to
// its claims — nothing more. It does NOT check DPoP sender-constraint
// binding, ordinary expiry, or revocation: Verify() enforces all three
// itself, once, uniformly for every implementation, by comparing the
// Thumbprint and ExpiresAt this method returns against the caller's
// already-verified DPoP proof and Dependencies.Revocation. Binding
// checking is structurally impossible here — ResolveAccessTokenRequest
// carries no expected thumbprint to compare against. Expiry checking
// is not similarly prevented (req.Now is available for other reasons,
// e.g. MaxLifetime enforcement), but an implementation MUST NOT
// perform its own — doing so would silently duplicate, and risk
// diverging from, logic Verify() already applies uniformly. Return the
// token's own claimed Thumbprint/ExpiresAt verbatim (e.g. a JWT's
// signature-verified cnf.jkt claim, or an opaque token's stored
// thumbprint) and let Verify() decide whether they're acceptable.
//
// Required — pass JWTAccessTokens{...} (the default),
// OpaqueAccessTokens{...}, or your own.
//
// A returned error should be a *Error (via this package's own
// newError, unexported but reachable from another file in this
// package) rather than a bare error — see ARCHITECTURE.md design rule
// 16, "Errors carry their own exposure": whether a failure is a
// client-facing invalid_token (401) or an operational server_error
// (500, e.g. IssuerKeys unreachable) is a distinction each
// AccessTokenResolver implementation is best placed to make, not
// something Verify() should collapse into one status for every
// failure reason. Verify() propagates a *Error unchanged; a bare error
// falls back to ErrorInvalidToken/401.
type AccessTokenResolver interface {
	ResolveAccessToken(ctx context.Context, req ResolveAccessTokenRequest) (ResolvedAccessToken, error)
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

// ResolveAccessToken implements AccessTokenResolver.
func (j JWTAccessTokens) ResolveAccessToken(ctx context.Context, req ResolveAccessTokenRequest) (ResolvedAccessToken, error) {
	parsed, err := token.ParseAccessToken(req.Raw)
	if err != nil {
		return ResolvedAccessToken{}, newError(ErrorInvalidToken, 401, "access token is malformed", err)
	}

	candidates, err := j.IssuerKeys.ResolveIssuerKeys(ctx, keys.IssuerKeyRequest{
		Issuer:    j.Issuer.String(),
		Purpose:   keys.AccessTokenVerification,
		Algorithm: j.Algorithm,
		KeyID:     parsed.KeyID(),
	})
	if err != nil {
		return ResolvedAccessToken{}, newError(ErrorServerError, 500, "failed to resolve issuer keys", err)
	}
	if len(candidates.Keys) == 0 {
		return ResolvedAccessToken{}, newError(ErrorInvalidToken, 401, "no matching issuer key", nil)
	}

	policy := token.AccessTokenValidatePolicy{
		ExpectedIssuer:   j.Issuer.String(),
		ExpectedAudience: j.Audience,
		Algorithm:        j.Algorithm,
		Now:              req.Now,
		MaxLifetime:      j.MaxTokenLifetime,
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
		return ResolvedAccessToken{}, newError(ErrorInvalidToken, 401, "access token is invalid", validErr)
	}

	var scopes []string
	if validated.Scope != "" {
		scopes = strings.Fields(validated.Scope)
	}
	return ResolvedAccessToken{
		Subject:    validated.Subject,
		ClientID:   validated.ClientID,
		Scopes:     scopes,
		Claims:     validated.Parameters,
		ExpiresAt:  validated.ExpiresAt,
		Thumbprint: validated.JKT,
		// internal/token.ValidatedAccessToken.JTI is NOT renamed — it's
		// internal, JWT-only by construction (internal/token never
		// handles opaque tokens, see internal/token/doc.go). Only this
		// package-level ResolvedAccessToken.Key is.
		Key: validated.JTI,
	}, nil
}

// OpaqueAccessTokens resolves opaque, storage-backed access tokens:
// hash the presented token and look it up — there is no signature to
// verify, and (see AccessTokenResolver's own doc comment) no DPoP
// binding or expiry check to perform here either; it returns the
// looked-up thumbprint/expiry verbatim for Verify() to check.
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

// ResolveAccessToken implements AccessTokenResolver.
func (o OpaqueAccessTokens) ResolveAccessToken(ctx context.Context, req ResolveAccessTokenRequest) (ResolvedAccessToken, error) {
	hash := sha256.Sum256([]byte(req.Raw))
	looked, err := o.Store.LookupAccessToken(ctx, storage.AccessTokenLookup{TokenHash: hash})
	if err != nil {
		return ResolvedAccessToken{}, newError(ErrorInvalidToken, 401, "access token is invalid", err)
	}
	return ResolvedAccessToken{
		Subject:    looked.Subject,
		ClientID:   looked.ClientID.String(),
		Scopes:     looked.Scope,
		Claims:     looked.Claims,
		ExpiresAt:  looked.ExpiresAt,
		Thumbprint: looked.Thumbprint,
		Key:        hex.EncodeToString(hash[:]),
	}, nil
}

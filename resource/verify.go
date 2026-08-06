package resource

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"github.com/osanderson/go-fapi/internal/dpop"
	"github.com/osanderson/go-fapi/internal/token"
	"github.com/osanderson/go-fapi/keys"
)

// VerifyRequest describes one incoming request to verify: the HTTP
// method and target URL it was made against, its raw Authorization
// header value, and its raw DPoP header value ("" if absent). Every
// access token this package accepts is DPoP-sender-constrained, so a
// request presenting a bearer token, or a DPoP-scheme token with no DPoP
// header, is rejected.
type VerifyRequest struct {
	Method        string
	URL           *url.URL
	Authorization string
	DPoPProof     string
}

// AuthorizationContext is what Verify returns for a successfully
// verified request: who is acting (Subject), on behalf of which client
// (ClientID), with what granted scope, and any additional claims the
// access token carried.
type AuthorizationContext struct {
	Subject   string
	ClientID  string
	Scopes    []string
	Claims    map[string]json.RawMessage
	ExpiresAt time.Time
}

// Verify checks req's Authorization header and DPoP proof together —
// token verification is inseparable from HTTP request context, so there
// is no bare VerifyJWT or VerifyDPoP entry point; see ARCHITECTURE.md,
// "Resource server verifies in HTTP context, not in isolation". On
// success it returns the AuthorizationContext the caller is granted; on
// failure it returns a typed Error describing what's safe to expose to
// the caller of the protected API.
func (v *Verifier) Verify(ctx context.Context, req VerifyRequest) (AuthorizationContext, error) {
	if req.Method == "" {
		return AuthorizationContext{}, newError(ErrorInvalidRequest, 400, "method is required", nil)
	}
	if req.URL == nil {
		return AuthorizationContext{}, newError(ErrorInvalidRequest, 400, "url is required", nil)
	}

	scheme, raw, ok := strings.Cut(req.Authorization, " ")
	if !ok || raw == "" {
		return AuthorizationContext{}, newError(ErrorInvalidRequest, 400, "authorization header is missing or malformed", nil)
	}
	if !strings.EqualFold(scheme, "DPoP") {
		return AuthorizationContext{}, newError(ErrorInvalidRequest, 400, "authorization scheme must be DPoP", nil)
	}
	if req.DPoPProof == "" {
		return AuthorizationContext{}, newError(ErrorInvalidRequest, 400, "DPoP header is required", nil)
	}

	parsed, err := token.ParseAccessToken(raw)
	if err != nil {
		return AuthorizationContext{}, newError(ErrorInvalidToken, 401, "access token is malformed", err)
	}

	now := v.deps.Clock.Now()

	verifiedProof, err := dpop.Verify(ctx, dpop.VerifyRequest{
		Proof:        req.DPoPProof,
		Method:       req.Method,
		URL:          req.URL,
		AccessToken:  raw,
		Now:          now,
		MaxProofAge:  v.cfg.Limits.MaxDPoPProofAge,
		MaxClockSkew: v.cfg.Limits.MaxClockSkew,
		Replay:       v.dpopReplayChecker(),
	})
	if err != nil {
		return AuthorizationContext{}, newError(ErrorInvalidToken, 401, "DPoP proof verification failed", err)
	}

	candidates, err := v.deps.IssuerKeys.ResolveIssuerKeys(ctx, keys.IssuerKeyRequest{
		Issuer:    v.cfg.Issuer.String(),
		Purpose:   keys.AccessTokenVerification,
		Algorithm: v.cfg.Algorithm,
		KeyID:     parsed.KeyID(),
	})
	if err != nil {
		return AuthorizationContext{}, newError(ErrorServerError, 500, "failed to resolve issuer keys", err)
	}
	if len(candidates.Keys) == 0 {
		return AuthorizationContext{}, newError(ErrorInvalidToken, 401, "no matching issuer key", nil)
	}

	policy := token.AccessTokenValidatePolicy{
		ExpectedIssuer:     v.cfg.Issuer.String(),
		ExpectedAudience:   v.cfg.Audience,
		Algorithm:          v.cfg.Algorithm,
		ExpectedThumbprint: &verifiedProof.Thumbprint,
		Now:                now,
		MaxLifetime:        v.cfg.Limits.MaxTokenLifetime,
		MaxClockSkew:       v.cfg.Limits.MaxClockSkew,
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
		return AuthorizationContext{}, newError(ErrorInvalidToken, 401, "access token is invalid", validErr)
	}

	var scopes []string
	if validated.Scope != "" {
		scopes = strings.Fields(validated.Scope)
	}

	return AuthorizationContext{
		Subject:   validated.Subject,
		ClientID:  validated.ClientID,
		Scopes:    scopes,
		Claims:    validated.Parameters,
		ExpiresAt: validated.ExpiresAt,
	}, nil
}

package resource

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"github.com/idfoundry/fapigo/internal/dpop"
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

	// Key is the access token's revocation-lookup identifier (see
	// ValidatedAccessToken.Key), exposed for a caller's own audit
	// logging — it's already available at this point (see
	// Dependencies.Revocation), so surfacing it costs nothing.
	Key string
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

	validated, err := v.deps.AccessTokens.VerifyAccessToken(ctx, VerifyAccessTokenRequest{
		Raw: raw, Thumbprint: verifiedProof.Thumbprint.String(),
		Now: now, MaxClockSkew: v.cfg.Limits.MaxClockSkew,
	})
	if err != nil {
		// A *Error carries its own exposure (see AccessTokenVerifier's
		// own doc comment on why that's the implementation's call, not
		// this method's) — propagate it unchanged. A bare error (a
		// third-party AccessTokenVerifier that didn't follow that
		// convention) falls back to the same invalid_token/401 every
		// other rejection here defaults to.
		if rerr, ok := err.(*Error); ok {
			return AuthorizationContext{}, rerr
		}
		return AuthorizationContext{}, newError(ErrorInvalidToken, 401, "access token is invalid", err)
	}

	revoked, err := v.deps.Revocation.IsRevoked(ctx, validated.Key)
	if err != nil {
		return AuthorizationContext{}, newError(ErrorServerError, 500, "failed to check token revocation", err)
	}
	if revoked {
		return AuthorizationContext{}, newError(ErrorInvalidToken, 401, "access token has been revoked", nil)
	}

	return AuthorizationContext{
		Subject:   validated.Subject,
		ClientID:  validated.ClientID,
		Scopes:    validated.Scopes,
		Claims:    validated.Claims,
		ExpiresAt: validated.ExpiresAt,
		Key:       validated.Key,
	}, nil
}

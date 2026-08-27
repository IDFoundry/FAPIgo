package resource

import (
	"context"
	"crypto/subtle"
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
	// ResolvedAccessToken.Key), exposed for a caller's own audit
	// logging — it's already available at this point (see
	// Dependencies.Revocation), so surfacing it costs nothing.
	Key string

	// NextDPoPNonce is a freshly issued DPoP nonce the caller should set
	// as this response's own DPoP-Nonce header, so its next call already
	// carries a valid one instead of needing its own challenge/retry
	// round trip (RFC 9449 §8's own proactive-refresh recommendation).
	// Always "" when Dependencies.Nonces is nil (nonce-challenge support
	// disabled); otherwise always populated on a successful Verify.
	NextDPoPNonce string
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

	// Nonce freshness is checked before spending the cost of resolving
	// the access token — a request that fails this cheap, early gate
	// shouldn't get as far as touching Dependencies.AccessTokens at all.
	if v.deps.Nonces != nil {
		if challenge := v.checkDPoPNonce(ctx, verifiedProof.Nonce, now); challenge != nil {
			return AuthorizationContext{}, challenge
		}
	}

	resolved, err := v.deps.AccessTokens.ResolveAccessToken(ctx, ResolveAccessTokenRequest{Raw: raw, Now: now})
	if err != nil {
		// A *Error carries its own exposure (see AccessTokenResolver's
		// own doc comment on why that's the implementation's call, not
		// this method's) — propagate it unchanged. A bare error (a
		// third-party AccessTokenResolver that didn't follow that
		// convention) falls back to the same invalid_token/401 every
		// other rejection here defaults to.
		if rerr, ok := err.(*Error); ok {
			return AuthorizationContext{}, rerr
		}
		return AuthorizationContext{}, newError(ErrorInvalidToken, 401, "access token is invalid", err)
	}

	// DPoP sender-constraint binding and ordinary expiry are enforced
	// here, once, uniformly for every AccessTokenResolver implementation
	// — see that interface's own doc comment for why this moved out of
	// each implementation. Constant-time: resolved.Thumbprint (from an
	// implementation that never set it) is "", which always
	// length-mismatches verifiedProof.Thumbprint.String() (always a
	// non-empty jose.Thumbprint encoding) and so always fails closed.
	if subtle.ConstantTimeCompare([]byte(resolved.Thumbprint), []byte(verifiedProof.Thumbprint.String())) != 1 {
		return AuthorizationContext{}, newError(ErrorInvalidToken, 401, "access token is not bound to the presented DPoP key", nil)
	}
	if now.After(resolved.ExpiresAt.Add(v.cfg.Limits.MaxClockSkew)) {
		return AuthorizationContext{}, newError(ErrorInvalidToken, 401, "access token has expired", nil)
	}

	revoked, err := v.deps.Revocation.IsRevoked(ctx, resolved.Key)
	if err != nil {
		return AuthorizationContext{}, newError(ErrorServerError, 500, "failed to check token revocation", err)
	}
	if revoked {
		return AuthorizationContext{}, newError(ErrorInvalidToken, 401, "access token has been revoked", nil)
	}

	var nextNonce string
	if v.deps.Nonces != nil {
		nextNonce, err = v.issueDPoPNonce(ctx, now)
		if err != nil {
			return AuthorizationContext{}, newError(ErrorServerError, 500, "failed to issue dpop nonce", err)
		}
	}

	return AuthorizationContext{
		Subject:       resolved.Subject,
		ClientID:      resolved.ClientID,
		Scopes:        resolved.Scopes,
		Claims:        resolved.Claims,
		ExpiresAt:     resolved.ExpiresAt,
		Key:           resolved.Key,
		NextDPoPNonce: nextNonce,
	}, nil
}

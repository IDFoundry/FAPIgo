package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"strings"

	fapi "github.com/osanderson/go-fapi"
	"github.com/osanderson/go-fapi/storage"
)

// RefreshTokenRequest is the input to Server.RefreshAccessToken.
type RefreshTokenRequest struct {
	HTTP FormRequest

	// DPoPProof is the value of the request's DPoP header. It is
	// required, and must be bound to the same key the original refresh
	// token was issued to.
	DPoPProof string
}

// RefreshAccessToken authenticates the client, verifies its DPoP proof,
// and redeems the refresh token — always rotating it: the presented
// token is consumed (a second use of the same token fails) and a new
// one is issued alongside the new access token. A requested scope may
// narrow, but never widen, the token's original grant.
func (s *Server) RefreshAccessToken(ctx context.Context, req RefreshTokenRequest) (TokenResult, error) {
	params, err := formParametersToMap(req.HTTP.Parameters)
	if err != nil {
		return s.tokenFail(ctx, AuditEventRefreshAccessToken, "", newError(ErrorInvalidRequest, 400, "the request contains a duplicated parameter", err))
	}

	if params["grant_type"] != "refresh_token" {
		return s.tokenFail(ctx, AuditEventRefreshAccessToken, "", newError(ErrorUnsupportedGrantType, 400, "grant_type must be refresh_token", nil))
	}

	client, _, authErr := s.authenticateClient(ctx, params)
	if authErr != nil {
		return s.tokenFail(ctx, AuditEventRefreshAccessToken, "", authErr)
	}

	rawToken := params["refresh_token"]
	if rawToken == "" {
		return s.tokenFail(ctx, AuditEventRefreshAccessToken, client.ID(), newError(ErrorInvalidRequest, 400, "refresh_token is required", nil))
	}

	verifiedProof, dpopErr := s.verifyTokenRequestDPoP(ctx, req.DPoPProof)
	if dpopErr != nil {
		return s.tokenFail(ctx, AuditEventRefreshAccessToken, client.ID(), dpopErr)
	}
	thumbprint := verifiedProof.Thumbprint.String()

	redeemed, err := s.deps.Grants.RedeemRefreshToken(ctx, storage.RefreshTokenRedemption{
		TokenHash: sha256.Sum256([]byte(rawToken)),
	})
	if err != nil {
		return s.tokenFail(ctx, AuditEventRefreshAccessToken, client.ID(), newError(ErrorInvalidGrant, 400, "refresh_token is invalid, expired, or already used", err))
	}

	now := s.deps.Clock.Now()
	if !now.Before(redeemed.ExpiresAt) {
		return s.tokenFail(ctx, AuditEventRefreshAccessToken, client.ID(), newError(ErrorInvalidGrant, 400, "refresh_token has expired", nil))
	}
	if redeemed.ClientID != client.ID() {
		return s.tokenFail(ctx, AuditEventRefreshAccessToken, client.ID(), newError(ErrorInvalidGrant, 400, "refresh_token was not issued to this client", nil))
	}
	if subtle.ConstantTimeCompare([]byte(thumbprint), []byte(redeemed.Thumbprint)) != 1 {
		return s.tokenFail(ctx, AuditEventRefreshAccessToken, client.ID(), newError(ErrorInvalidGrant, 400, "DPoP proof key does not match refresh_token", nil))
	}

	scope := redeemed.Scope
	if requestedScope, ok := params["scope"]; ok && requestedScope != "" {
		narrowed := strings.Fields(requestedScope)
		if err := validateGrantedScopeSubset(narrowed, strings.Join(redeemed.Scope, " ")); err != nil {
			return s.tokenFail(ctx, AuditEventRefreshAccessToken, client.ID(), newError(ErrorInvalidScope, 400, "requested scope exceeds the original grant", err))
		}
		scope = narrowed
	}

	accessTokenClaims, err := withRequestedUserinfoClaims(redeemed.RequestedUserinfoClaims, redeemed.TokenClaims)
	if err != nil {
		return s.tokenFail(ctx, AuditEventRefreshAccessToken, client.ID(), newError(ErrorServerError, 500, "failed to encode requested userinfo claims", err))
	}
	accessToken, err := s.issueAccessToken(ctx, client.ID(), redeemed.Subject, scope, thumbprint, accessTokenClaims)
	if err != nil {
		return s.tokenFail(ctx, AuditEventRefreshAccessToken, client.ID(), newError(ErrorServerError, 500, "failed to issue access token", err))
	}

	result := TokenResult{
		AccessToken: fapi.NewSecret(accessToken),
		TokenType:   "DPoP",
		ExpiresIn:   s.cfg.Limits.AccessTokenLifetime,
		Scope:       strings.Join(scope, " "),
	}

	if containsScope(scope, "openid") {
		// A refreshed ID token omits nonce — it was only ever meant to
		// bind the *original* ID token to the authorization request that
		// requested it, not to every subsequent refresh.
		idTokenClaims, err := s.withIdentityClaims(ctx, redeemed.Subject, redeemed.RequestedIDTokenClaims, redeemed.TokenClaims)
		if err != nil {
			return s.tokenFail(ctx, AuditEventRefreshAccessToken, client.ID(), newError(ErrorServerError, 500, "failed to resolve identity claims", err))
		}
		idToken, err := s.issueIDToken(ctx, client.ID(), redeemed.Subject, "", redeemed.AuthTime, redeemed.ACR, redeemed.AMR, idTokenClaims)
		if err != nil {
			return s.tokenFail(ctx, AuditEventRefreshAccessToken, client.ID(), newError(ErrorServerError, 500, "failed to issue ID token", err))
		}
		result.IDToken = fapi.NewSecret(idToken)
		result.HasIDToken = true
	}

	refreshToken, err := s.issueRefreshToken(ctx, client.ID(), redeemed.Subject, scope, thumbprint, redeemed.AuthTime, redeemed.ACR, redeemed.AMR, redeemed.TokenClaims, redeemed.RequestedIDTokenClaims, redeemed.RequestedUserinfoClaims)
	if err != nil {
		return s.tokenFail(ctx, AuditEventRefreshAccessToken, client.ID(), newError(ErrorServerError, 500, "failed to issue refresh token", err))
	}
	result.RefreshToken = fapi.NewSecret(refreshToken)
	result.HasRefreshToken = true

	s.audit(ctx, AuditEventRefreshAccessToken, client.ID(), AuditOutcomeSuccess, "")
	return result, nil
}

package server

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/storage"
)

// CIBAGrantType is the grant_type value CIBA's token-endpoint polling
// step uses (CIBA §10.1). Exported so an HTTP adapter's own grant_type
// dispatch (there is no in-package dispatcher — see
// ExchangeAuthorizationCode/RefreshAccessToken's own doc comments) can
// route to ExchangeBackchannelAuthentication.
const CIBAGrantType = "urn:openid:params:grant-type:ciba"

// BackchannelTokenExchangeRequest is the input to
// Server.ExchangeBackchannelAuthentication.
type BackchannelTokenExchangeRequest struct {
	HTTP FormRequest

	// DPoPProof is the value of the request's DPoP header. Required —
	// every access token this server issues is DPoP-sender-constrained,
	// the same requirement ExchangeAuthorizationCode/RefreshAccessToken
	// already have.
	DPoPProof string
}

// ExchangeBackchannelAuthentication authenticates the client, verifies
// its DPoP proof, and polls the pending backchannel authentication
// request identified by auth_req_id: if no decision has been recorded
// yet, it fails with ErrorAuthorizationPending; once denied or the end
// user failed to authenticate, it fails with ErrorAccessDenied; once
// approved, it issues an access token bound to the DPoP key (plus an ID
// token when the granted scope included "openid" and a refresh token
// when it included "offline_access") — exactly once, mirroring
// ExchangeAuthorizationCode's single-issuance guarantee.
func (s *Server) ExchangeBackchannelAuthentication(ctx context.Context, req BackchannelTokenExchangeRequest) (TokenResult, error) {
	params, err := formParametersToMap(req.HTTP.Parameters)
	if err != nil {
		return s.tokenFail(ctx, AuditEventExchangeBackchannelAuthentication, "", newError(ErrorInvalidRequest, 400, "the request contains a duplicated parameter", err))
	}

	if params["grant_type"] != CIBAGrantType {
		return s.tokenFail(ctx, AuditEventExchangeBackchannelAuthentication, "", newError(ErrorUnsupportedGrantType, 400, "grant_type must be "+CIBAGrantType, nil))
	}

	client, _, authErr := s.authenticateClient(ctx, params)
	if authErr != nil {
		return s.tokenFail(ctx, AuditEventExchangeBackchannelAuthentication, "", authErr)
	}

	authReqID := params["auth_req_id"]
	if authReqID == "" {
		return s.tokenFail(ctx, AuditEventExchangeBackchannelAuthentication, client.ID(), newError(ErrorInvalidRequest, 400, "auth_req_id is required", nil))
	}

	verifiedProof, dpopErr := s.verifyTokenRequestDPoP(ctx, req.DPoPProof)
	if dpopErr != nil {
		return s.tokenFail(ctx, AuditEventExchangeBackchannelAuthentication, client.ID(), dpopErr)
	}
	thumbprint := verifiedProof.Thumbprint.String()

	now := s.deps.Clock.Now()
	polled, err := s.deps.Backchannel.PollBackchannelAuthentication(ctx, storage.PollBackchannelAuthentication{
		AuthReqIDHash: sha256.Sum256([]byte(authReqID)),
		Now:           now,
	})
	if err != nil {
		var expired *storage.BackchannelAuthenticationExpiredError
		if errors.As(err, &expired) {
			return s.tokenFail(ctx, AuditEventExchangeBackchannelAuthentication, client.ID(), newError(ErrorExpiredToken, 400, "auth_req_id has expired", err))
		}
		var slowDown *storage.BackchannelAuthenticationSlowDownError
		if errors.As(err, &slowDown) {
			return s.tokenFail(ctx, AuditEventExchangeBackchannelAuthentication, client.ID(), newError(ErrorSlowDown, 400, "polled faster than the configured interval", err))
		}
		var alreadyRedeemed *storage.BackchannelAuthenticationAlreadyRedeemedError
		if errors.As(err, &alreadyRedeemed) {
			return s.tokenFail(ctx, AuditEventExchangeBackchannelAuthentication, client.ID(), newError(ErrorInvalidGrant, 400, "auth_req_id has already been used", err))
		}
		return s.tokenFail(ctx, AuditEventExchangeBackchannelAuthentication, client.ID(), newError(ErrorInvalidGrant, 400, "auth_req_id is invalid or unknown", err))
	}

	if polled.ClientID != client.ID() {
		return s.tokenFail(ctx, AuditEventExchangeBackchannelAuthentication, client.ID(), newError(ErrorInvalidGrant, 400, "auth_req_id was not issued to this client", nil))
	}
	if polled.DPoPJKT != "" && polled.DPoPJKT != thumbprint {
		return s.tokenFail(ctx, AuditEventExchangeBackchannelAuthentication, client.ID(), newError(ErrorInvalidGrant, 400, "DPoP proof key does not match the dpop_jkt bound to this backchannel authentication request", nil))
	}

	switch polled.Status {
	case storage.BackchannelAuthenticationPending:
		return s.tokenFail(ctx, AuditEventExchangeBackchannelAuthentication, client.ID(), newError(ErrorAuthorizationPending, 400, "the end user has not yet completed authentication", nil))
	case storage.BackchannelAuthenticationDenied, storage.BackchannelAuthenticationAuthenticationFailed:
		return s.tokenFail(ctx, AuditEventExchangeBackchannelAuthentication, client.ID(), newError(ErrorAccessDenied, 400, "the end user denied the request, or could not be authenticated", nil))
	case storage.BackchannelAuthenticationApproved:
		// fall through to issuance below
	default:
		return s.tokenFail(ctx, AuditEventExchangeBackchannelAuthentication, client.ID(), newError(ErrorServerError, 500, "unrecognized backchannel authentication status", nil))
	}

	accessTokenClaims, err := withRequestedUserinfoClaims(polled.RequestedUserinfoClaims, polled.TokenClaims)
	if err != nil {
		return s.tokenFail(ctx, AuditEventExchangeBackchannelAuthentication, client.ID(), newError(ErrorServerError, 500, "failed to encode requested userinfo claims", err))
	}
	accessToken, _, err := s.deps.AccessTokens.IssueAccessToken(ctx, AccessTokenParams{
		ClientID: client.ID(), Subject: polled.Subject, Scope: polled.Scope,
		Thumbprint: thumbprint, Claims: accessTokenClaims,
		Issuer: s.cfg.Issuer.String(), Audience: s.cfg.Issuer.String(),
		Now: now, Lifetime: s.cfg.Limits.AccessTokenLifetime, Random: s.deps.Random,
	})
	if err != nil {
		return s.tokenFail(ctx, AuditEventExchangeBackchannelAuthentication, client.ID(), newError(ErrorServerError, 500, "failed to issue access token", err))
	}

	result := TokenResult{
		AccessToken: fapi.NewSecret(accessToken),
		TokenType:   "DPoP",
		ExpiresIn:   s.cfg.Limits.AccessTokenLifetime,
		Scope:       strings.Join(polled.Scope, " "),
	}

	if containsScope(polled.Scope, "openid") {
		idTokenClaims, err := s.withIdentityClaims(ctx, polled.Subject, polled.RequestedIDTokenClaims, polled.TokenClaims)
		if err != nil {
			return s.tokenFail(ctx, AuditEventExchangeBackchannelAuthentication, client.ID(), newError(ErrorServerError, 500, "failed to resolve identity claims", err))
		}
		idToken, err := s.issueIDToken(ctx, client, identityAssertion{
			Subject: polled.Subject, AuthTime: polled.AuthTime, ACR: polled.ACR, AMR: polled.AMR, TokenClaims: idTokenClaims,
		}, "")
		if err != nil {
			return s.tokenFail(ctx, AuditEventExchangeBackchannelAuthentication, client.ID(), newError(ErrorServerError, 500, "failed to issue ID token", err))
		}
		result.IDToken = fapi.NewSecret(idToken)
		result.HasIDToken = true
	}

	if containsScope(polled.Scope, "offline_access") {
		refreshToken, err := s.issueRefreshToken(ctx, client.ID(), identityAssertion{
			Subject: polled.Subject, AuthTime: polled.AuthTime, ACR: polled.ACR, AMR: polled.AMR, TokenClaims: polled.TokenClaims,
		}, polled.Scope, thumbprint, polled.RequestedIDTokenClaims, polled.RequestedUserinfoClaims)
		if err != nil {
			return s.tokenFail(ctx, AuditEventExchangeBackchannelAuthentication, client.ID(), newError(ErrorServerError, 500, "failed to issue refresh token", err))
		}
		result.RefreshToken = fapi.NewSecret(refreshToken)
		result.HasRefreshToken = true
	}

	if s.deps.Nonces != nil {
		nextNonce, err := s.issueDPoPNonce(ctx, now)
		if err != nil {
			return s.tokenFail(ctx, AuditEventExchangeBackchannelAuthentication, client.ID(), newError(ErrorServerError, 500, "failed to issue dpop nonce", err))
		}
		result.NextDPoPNonce = nextNonce
	}

	s.audit(ctx, AuditEventExchangeBackchannelAuthentication, client.ID(), AuditOutcomeSuccess, "")
	return result, nil
}

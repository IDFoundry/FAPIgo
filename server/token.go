package server

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/dpop"
	"github.com/idfoundry/fapigo/internal/pkce"
	"github.com/idfoundry/fapigo/internal/token"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/storage"
)

// AuthorizationCodeExchangeRequest is the input to
// Server.ExchangeAuthorizationCode.
type AuthorizationCodeExchangeRequest struct {
	HTTP FormRequest

	// DPoPProof is the value of the request's DPoP header. It is
	// required — every access token this server issues is
	// DPoP-sender-constrained.
	DPoPProof string
}

// TokenResult is returned by a successful ExchangeAuthorizationCode or
// RefreshAccessToken.
type TokenResult struct {
	AccessToken fapi.Secret
	TokenType   string // always "DPoP"
	ExpiresIn   time.Duration
	Scope       string

	// IDToken is set only when the granted scope included "openid".
	IDToken    fapi.Secret
	HasIDToken bool

	// RefreshToken is set only when the granted scope included
	// "offline_access" (ExchangeAuthorizationCode) or on every
	// successful RefreshAccessToken call, which always rotates it.
	RefreshToken    fapi.Secret
	HasRefreshToken bool
}

// ExchangeAuthorizationCode authenticates the client, verifies its DPoP
// proof, redeems the authorization code (single-use — a second exchange
// with the same code fails), checks PKCE and redirect_uri, and issues an
// access token bound to the DPoP key, plus an ID token when the granted
// scope included "openid" and a refresh token when it included
// "offline_access".
func (s *Server) ExchangeAuthorizationCode(ctx context.Context, req AuthorizationCodeExchangeRequest) (TokenResult, error) {
	params, err := formParametersToMap(req.HTTP.Parameters)
	if err != nil {
		return s.tokenFail(ctx, AuditEventExchangeAuthorizationCode, "", newError(ErrorInvalidRequest, 400, "the request contains a duplicated parameter", err))
	}

	if params["grant_type"] != "authorization_code" {
		return s.tokenFail(ctx, AuditEventExchangeAuthorizationCode, "", newError(ErrorUnsupportedGrantType, 400, "grant_type must be authorization_code", nil))
	}

	client, _, authErr := s.authenticateClient(ctx, params)
	if authErr != nil {
		return s.tokenFail(ctx, AuditEventExchangeAuthorizationCode, "", authErr)
	}

	code := params["code"]
	if code == "" {
		return s.tokenFail(ctx, AuditEventExchangeAuthorizationCode, client.ID(), newError(ErrorInvalidRequest, 400, "code is required", nil))
	}
	redirectURI := params["redirect_uri"]
	if redirectURI == "" {
		return s.tokenFail(ctx, AuditEventExchangeAuthorizationCode, client.ID(), newError(ErrorInvalidRequest, 400, "redirect_uri is required", nil))
	}
	codeVerifier := params["code_verifier"]
	if codeVerifier == "" {
		// invalid_grant, not invalid_request: RFC 7636 §4.6 treats a
		// code_verifier problem as a grant-validity failure, not a
		// malformed-request one — a missing verifier is judged the same
		// way as a mismatched one (below), covering the case where PKCE
		// was required for the authorization but the token request omits
		// the verifier entirely.
		return s.tokenFail(ctx, AuditEventExchangeAuthorizationCode, client.ID(), newError(ErrorInvalidGrant, 400, "code_verifier is required", nil))
	}

	verifiedProof, dpopErr := s.verifyTokenRequestDPoP(ctx, req.DPoPProof)
	if dpopErr != nil {
		return s.tokenFail(ctx, AuditEventExchangeAuthorizationCode, client.ID(), dpopErr)
	}
	thumbprint := verifiedProof.Thumbprint.String()

	redeemed, err := s.deps.Grants.RedeemAuthorizationCode(ctx, storage.AuthorizationCodeRedemption{
		CodeHash: sha256.Sum256([]byte(code)),
	})
	if err != nil {
		return s.tokenFail(ctx, AuditEventExchangeAuthorizationCode, client.ID(), newError(ErrorInvalidGrant, 400, "code is invalid, expired, or already used", err))
	}

	now := s.deps.Clock.Now()
	if !now.Before(redeemed.ExpiresAt) {
		return s.tokenFail(ctx, AuditEventExchangeAuthorizationCode, client.ID(), newError(ErrorInvalidGrant, 400, "code has expired", nil))
	}
	if redeemed.ClientID != client.ID() {
		return s.tokenFail(ctx, AuditEventExchangeAuthorizationCode, client.ID(), newError(ErrorInvalidGrant, 400, "code was not issued to this client", nil))
	}
	if !fapi.RegisteredRedirectURI(redeemed.RedirectURI).Equal(redirectURI) {
		return s.tokenFail(ctx, AuditEventExchangeAuthorizationCode, client.ID(), newError(ErrorInvalidGrant, 400, "redirect_uri does not match the authorization request", nil))
	}
	if redeemed.DPoPJKT != "" && redeemed.DPoPJKT != thumbprint {
		return s.tokenFail(ctx, AuditEventExchangeAuthorizationCode, client.ID(), newError(ErrorInvalidGrant, 400, "DPoP proof key does not match the dpop_jkt bound to this authorization code", nil))
	}
	if err := pkce.Verify(redeemed.CodeChallenge, pkce.S256, codeVerifier); err != nil {
		return s.tokenFail(ctx, AuditEventExchangeAuthorizationCode, client.ID(), newError(ErrorInvalidGrant, 400, "code_verifier does not match code_challenge", err))
	}

	accessTokenClaims, err := withRequestedUserinfoClaims(redeemed.RequestedUserinfoClaims, redeemed.TokenClaims)
	if err != nil {
		return s.tokenFail(ctx, AuditEventExchangeAuthorizationCode, client.ID(), newError(ErrorServerError, 500, "failed to encode requested userinfo claims", err))
	}
	accessToken, err := s.issueAccessToken(ctx, client.ID(), redeemed.Subject, redeemed.Scope, thumbprint, accessTokenClaims)
	if err != nil {
		return s.tokenFail(ctx, AuditEventExchangeAuthorizationCode, client.ID(), newError(ErrorServerError, 500, "failed to issue access token", err))
	}

	result := TokenResult{
		AccessToken: fapi.NewSecret(accessToken),
		TokenType:   "DPoP",
		ExpiresIn:   s.cfg.Limits.AccessTokenLifetime,
		Scope:       strings.Join(redeemed.Scope, " "),
	}

	if containsScope(redeemed.Scope, "openid") {
		idTokenClaims, err := s.withIdentityClaims(ctx, redeemed.Subject, redeemed.RequestedIDTokenClaims, redeemed.TokenClaims)
		if err != nil {
			return s.tokenFail(ctx, AuditEventExchangeAuthorizationCode, client.ID(), newError(ErrorServerError, 500, "failed to resolve identity claims", err))
		}
		idToken, err := s.issueIDToken(ctx, client.ID(), redeemed.Subject, redeemed.Nonce, redeemed.AuthTime, redeemed.ACR, redeemed.AMR, idTokenClaims)
		if err != nil {
			return s.tokenFail(ctx, AuditEventExchangeAuthorizationCode, client.ID(), newError(ErrorServerError, 500, "failed to issue ID token", err))
		}
		result.IDToken = fapi.NewSecret(idToken)
		result.HasIDToken = true
	}

	if containsScope(redeemed.Scope, "offline_access") {
		refreshToken, err := s.issueRefreshToken(ctx, client.ID(), redeemed.Subject, redeemed.Scope, thumbprint, redeemed.AuthTime, redeemed.ACR, redeemed.AMR, redeemed.TokenClaims, redeemed.RequestedIDTokenClaims, redeemed.RequestedUserinfoClaims)
		if err != nil {
			return s.tokenFail(ctx, AuditEventExchangeAuthorizationCode, client.ID(), newError(ErrorServerError, 500, "failed to issue refresh token", err))
		}
		result.RefreshToken = fapi.NewSecret(refreshToken)
		result.HasRefreshToken = true
	}

	s.audit(ctx, AuditEventExchangeAuthorizationCode, client.ID(), AuditOutcomeSuccess, "")
	return result, nil
}

func (s *Server) verifyTokenRequestDPoP(ctx context.Context, proof string) (dpop.VerifiedProof, *Error) {
	if proof == "" {
		return dpop.VerifiedProof{}, newError(ErrorInvalidRequest, 400, "DPoP proof is required", nil)
	}
	tokenEndpoint := s.cfg.Endpoints.Token.URL()
	verified, err := dpop.Verify(ctx, dpop.VerifyRequest{
		Proof:        proof,
		Method:       "POST",
		URL:          &tokenEndpoint,
		Now:          s.deps.Clock.Now(),
		MaxProofAge:  s.cfg.Limits.MaxDPoPProofAge,
		MaxClockSkew: s.cfg.Limits.MaxClockSkew,
		Replay:       s.dpopReplayChecker(),
	})
	if err != nil {
		return dpop.VerifiedProof{}, newError(ErrorInvalidRequest, 400, "DPoP proof verification failed", err)
	}
	return verified, nil
}

func (s *Server) issueAccessToken(ctx context.Context, clientID fapi.ClientID, subject string, scope []string, thumbprint string, tokenClaims map[string]json.RawMessage) (string, error) {
	signer, kid, err := s.newSigner(ctx, keys.AccessTokenSigning, s.cfg.Algorithms.AccessToken)
	if err != nil {
		return "", err
	}
	return token.IssueAccessToken(token.AccessTokenParams{
		Signer: signer, Algorithm: s.cfg.Algorithms.AccessToken, KeyID: kid,
		Issuer: s.cfg.Issuer.String(), Subject: subject, Audience: s.cfg.Issuer.String(),
		ClientID:     clientID.String(),
		Scope:        strings.Join(scope, " "),
		Confirmation: &token.Confirmation{JKT: thumbprint},
		Now:          s.deps.Clock.Now(), Lifetime: s.cfg.Limits.AccessTokenLifetime,
		Random:     s.deps.Random,
		Parameters: tokenClaims,
	})
}

// withIdentityClaims merges whatever Dependencies.IdentityClaims
// resolves for subject on top of base (base's keys win on collision —
// identity claims are additive, not a replacement for whatever a
// protocol extension already put there). A nil IdentityClaims is not an
// error; it just means no identity claims are added.
func (s *Server) withIdentityClaims(ctx context.Context, subject string, names []string, base map[string]json.RawMessage) (map[string]json.RawMessage, error) {
	if s.deps.IdentityClaims == nil || len(names) == 0 {
		return base, nil
	}
	identity, err := s.deps.IdentityClaims.ResolveIdentityClaims(ctx, subject, names)
	if err != nil {
		return nil, err
	}
	if len(identity) == 0 {
		return base, nil
	}
	merged := make(map[string]json.RawMessage, len(base)+len(identity))
	for k, v := range identity {
		merged[k] = v
	}
	for k, v := range base {
		merged[k] = v
	}
	return merged, nil
}

// withRequestedUserinfoClaims embeds names under
// RequestedUserinfoClaimsKey into base, for the access token only — an
// embedder's own UserInfo endpoint has no other way to learn which
// claims the original authorization request asked for (see
// RequestedUserinfoClaimsKey's doc comment). A nil/empty names leaves
// base untouched: no claims were requested, so there is nothing to
// record.
func withRequestedUserinfoClaims(names []string, base map[string]json.RawMessage) (map[string]json.RawMessage, error) {
	if len(names) == 0 {
		return base, nil
	}
	encoded, err := json.Marshal(names)
	if err != nil {
		return nil, err
	}
	merged := make(map[string]json.RawMessage, len(base)+1)
	for k, v := range base {
		merged[k] = v
	}
	merged[RequestedUserinfoClaimsKey] = encoded
	return merged, nil
}

func (s *Server) issueIDToken(ctx context.Context, clientID fapi.ClientID, subject, nonce string, authTime time.Time, acr string, amr []string, tokenClaims map[string]json.RawMessage) (string, error) {
	signer, kid, err := s.newSigner(ctx, keys.IDTokenSigning, s.cfg.Algorithms.IDToken)
	if err != nil {
		return "", err
	}
	return token.IssueIDToken(token.IDTokenParams{
		Signer: signer, Algorithm: s.cfg.Algorithms.IDToken, KeyID: kid,
		Issuer: s.cfg.Issuer.String(), Subject: subject, Audience: clientID.String(),
		Nonce: nonce, AuthTime: authTime, ACR: acr, AMR: amr,
		Now: s.deps.Clock.Now(), Lifetime: s.cfg.Limits.IDTokenLifetime,
		Parameters: tokenClaims,
	})
}

// issueRefreshToken generates and persists a new refresh token, returning
// its raw value.
func (s *Server) issueRefreshToken(ctx context.Context, clientID fapi.ClientID, subject string, scope []string, thumbprint string, authTime time.Time, acr string, amr []string, tokenClaims map[string]json.RawMessage, requestedIDTokenClaims, requestedUserinfoClaims []string) (string, error) {
	raw, err := generateRefreshToken(s.deps.Random)
	if err != nil {
		return "", err
	}
	now := s.deps.Clock.Now()
	if err := s.deps.Grants.CreateRefreshToken(ctx, storage.NewRefreshToken{
		TokenHash:               sha256.Sum256([]byte(raw)),
		ClientID:                clientID,
		Subject:                 subject,
		Scope:                   scope,
		Thumbprint:              thumbprint,
		AuthTime:                authTime,
		ACR:                     acr,
		AMR:                     amr,
		TokenClaims:             tokenClaims,
		RequestedIDTokenClaims:  requestedIDTokenClaims,
		RequestedUserinfoClaims: requestedUserinfoClaims,
		ExpiresAt:               now.Add(s.cfg.Limits.RefreshTokenLifetime),
	}); err != nil {
		return "", err
	}
	return raw, nil
}

func containsScope(scopes []string, target string) bool {
	for _, s := range scopes {
		if s == target {
			return true
		}
	}
	return false
}

func (s *Server) tokenFail(ctx context.Context, eventType AuditEventType, clientID fapi.ClientID, err *Error) (TokenResult, error) {
	s.audit(ctx, eventType, clientID, AuditOutcomeFailure, string(err.Code()))
	return TokenResult{}, err
}

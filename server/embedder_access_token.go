package server

import (
	"context"
	"encoding/json"
	"strings"

	fapi "github.com/idfoundry/fapigo"
)

// IssueAccessTokenRequest is a grant the embedder served itself, for
// IssueAccessToken to issue an access token for. Its fields mean exactly
// what IssueRefreshTokenRequest's do, and are checked the same way.
type IssueAccessTokenRequest struct {
	// GrantType is the grant the embedder served: one of
	// Config.AdditionalGrantTypes, such as OpenID4VCI's
	// urn:ietf:params:oauth:grant-type:pre-authorized_code.
	GrantType string

	// Client is the client the token request authenticated as, exactly
	// as AuthenticateAttestedClient returned it for this request: one
	// whose Client was changed is refused, and so is one whose
	// attestation expired more than Limits.MaxClockSkew ago, kept from an
	// earlier request.
	Client AttestedClient

	// Binding is the token request's sender-constraining credential,
	// exactly as VerifyTokenRequestBinding returned it for Client: the
	// access token is bound to it (its "cnf" claim), so one built by
	// hand, or verified for another client, is refused.
	Binding TokenBinding

	// Subject is the access token's sub.
	Subject SubjectID

	// Scope and AuthorizationDetails are what the access token grants.
	// At least one is required. Scope must be among the client's
	// AllowedScopes, and may not include "openid": no user
	// authenticated, so no ID token is issued. AuthorizationDetails must
	// parse under Config.RAR, in types the client is registered for; no
	// RARPolicy is consulted, since the embedder decided what to grant.
	Scope                []string
	AuthorizationDetails []json.RawMessage

	// GrantID, if set, names the grant, as IssueRefreshTokenRequest's
	// GrantID does: the access token carries it, so RevokeGrant ends
	// this token too, not only the ones a refresh issues later. Give a
	// refresh token issued for the same grant the same GrantID. A
	// GrantID already revoked is invalid_grant.
	GrantID string
}

// IssueAccessToken issues an access token for a grant the embedder
// served itself (Config.AdditionalGrantTypes), as this server's own
// token endpoint would: through Dependencies.AccessTokens, with this
// server's issuer, audience and Limits.AccessTokenLifetime, bound to
// req.Binding, and carrying the same claims as the access tokens a
// refresh token for the grant (IssueRefreshToken) later issues. Use it
// rather than calling Dependencies.AccessTokens directly: the claims
// that make the token revocable (GrantID) are the server's to set.
//
// The result is the token response, without a refresh token: to issue
// one too, call IssueRefreshToken with the same request and GrantID,
// then set the result's RefreshToken and HasRefreshToken before
// TokenResult.WriteJSON. With a GrantID, RevokeGrant, or RevokeToken on
// that refresh token, ends both. NextDPoPNonce is req.Binding's.
//
// Errors are *Error, as at this server's token endpoint. Every call
// records an AuditEventIssueAccessToken.
func (s *Server) IssueAccessToken(ctx context.Context, req IssueAccessTokenRequest) (TokenResult, error) {
	client := req.Client.Client
	grant, err := s.embedderGrant(ctx, embedderGrantRequest(req))
	if err == nil && req.Binding.verifiedFor != client.ID() {
		err = newError(ErrorServerError, 500, "Binding must be as VerifyTokenRequestBinding returned it for Client", nil)
	}
	if err != nil {
		s.audit(ctx, AuditEventIssueAccessToken, client.ID(), AuditOutcomeFailure, string(err.Code()))
		return TokenResult{}, err
	}
	claims, claimsErr := grant.accessTokenClaims()
	if claimsErr != nil {
		err := newError(ErrorServerError, 500, "failed to encode access token claims", claimsErr)
		s.audit(ctx, AuditEventIssueAccessToken, client.ID(), AuditOutcomeFailure, string(err.Code()))
		return TokenResult{}, err
	}
	accessToken, _, issueErr := s.deps.AccessTokens.IssueAccessToken(ctx, AccessTokenParams{
		ClientID: client.ID(), Subject: grant.Subject, Scope: grant.Scope,
		Thumbprint: req.Binding.Thumbprint, SenderConstrain: client.SenderConstrain(), Claims: claims,
		Issuer: s.cfg.Issuer.String(), Audience: s.cfg.Issuer.String(),
		Now: s.deps.Clock.Now(), Lifetime: s.cfg.Limits.AccessTokenLifetime, Random: s.deps.Random,
	})
	if issueErr != nil {
		err := newError(ErrorServerError, 500, "failed to issue access token", issueErr)
		s.audit(ctx, AuditEventIssueAccessToken, client.ID(), AuditOutcomeFailure, string(err.Code()))
		return TokenResult{}, err
	}
	s.audit(ctx, AuditEventIssueAccessToken, client.ID(), AuditOutcomeSuccess, "")
	return TokenResult{
		AccessToken:          fapi.NewSecret(accessToken),
		TokenType:            tokenTypeFor(client.SenderConstrain()),
		ExpiresIn:            s.cfg.Limits.AccessTokenLifetime,
		Scope:                strings.Join(grant.Scope, " "),
		AuthorizationDetails: grant.AuthorizationDetails,
		NextDPoPNonce:        req.Binding.NextDPoPNonce,
	}, nil
}

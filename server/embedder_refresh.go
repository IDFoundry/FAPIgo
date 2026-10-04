package server

import (
	"context"
	"encoding/json"
	"slices"

	fapi "github.com/idfoundry/fapigo"
)

// IssueRefreshTokenRequest is a grant the embedder served itself, for
// IssueRefreshToken to issue a refresh token for.
type IssueRefreshTokenRequest struct {
	// GrantType is the grant the embedder served: one of
	// Config.AdditionalGrantTypes, such as OpenID4VCI's
	// urn:ietf:params:oauth:grant-type:pre-authorized_code.
	GrantType string

	// Client is the client the token request authenticated as, exactly
	// as AuthenticateAttestedClient returned it for this request: one
	// whose Client was changed is refused. The refresh token is bound to its
	// Client Instance Key (draft-ietf-oauth-attestation-based-client-auth-07
	// §10.3): RefreshAccessToken redeems it only with an attestation for
	// that same key.
	Client AttestedClient

	// Binding is the token request's sender-constraining credential,
	// from VerifyTokenRequestBinding for Client. It must name a
	// credential of the client's registered kind; its thumbprint is
	// recorded with the grant for reference only, since a refresh binds
	// its access token to whichever key that request presents.
	Binding TokenBinding

	// Subject is the sub of every access token a refresh issues.
	Subject SubjectID

	// Scope and AuthorizationDetails are what every refresh grants, at
	// most: a refresh may narrow the scope, never widen it, and carries
	// the authorization details unchanged. At least one is required.
	// Scope must be among the client's AllowedScopes, and may not
	// include "openid": no user authenticated, so a refresh issues no
	// ID token. AuthorizationDetails must parse under Config.RAR, in
	// types the client is registered for; no RARPolicy is consulted,
	// since the embedder decided what to grant.
	Scope                []string
	AuthorizationDetails []json.RawMessage

	// GrantID, if set, names the grant so RevokeGrant can revoke it, as
	// GrantedAuthorization.GrantID does — and, like it, must name this
	// grant only. RevokeToken's TokenRevocationResult names it when the
	// client ends the grant.
	GrantID string
}

// IssueRefreshToken issues a refresh token for a grant the embedder
// served itself (Config.AdditionalGrantTypes), which RefreshAccessToken
// then redeems exactly as it does this server's own: reissuing an access
// token for the grant's subject, scope and authorization details, bound
// to whichever key the refresh request presents. The token isn't
// rotated, and lasts Limits.RefreshTokenLifetime.
//
// Whether to issue one is the embedder's decision: unlike the
// authorization code flow, the scope needn't include "offline_access".
// The embedder writes the token response itself, with the returned
// token as refresh_token. Errors are *Error, as at this server's token
// endpoint. Every call records an AuditEventIssueRefreshToken.
func (s *Server) IssueRefreshToken(ctx context.Context, req IssueRefreshTokenRequest) (fapi.Secret, error) {
	client := req.Client.Client
	grant, err := s.embedderRefreshGrant(req)
	if err != nil {
		s.audit(ctx, AuditEventIssueRefreshToken, client.ID(), AuditOutcomeFailure, string(err.Code()))
		return fapi.Secret{}, err
	}
	raw, issueErr := s.issueRefreshToken(ctx, client.ID(), grant, req.Binding.Thumbprint, req.Client.instanceKey)
	if issueErr != nil {
		err := newError(ErrorServerError, 500, "failed to issue refresh token", issueErr)
		s.audit(ctx, AuditEventIssueRefreshToken, client.ID(), AuditOutcomeFailure, string(err.Code()))
		return fapi.Secret{}, err
	}
	s.audit(ctx, AuditEventIssueRefreshToken, client.ID(), AuditOutcomeSuccess, "")
	return fapi.NewSecret(raw), nil
}

// embedderRefreshGrant validates req and returns the grant a refresh
// token for it carries.
func (s *Server) embedderRefreshGrant(req IssueRefreshTokenRequest) (grantRecord, *Error) {
	client := req.Client.Client
	switch {
	case !slices.Contains(s.cfg.AdditionalGrantTypes, req.GrantType):
		return grantRecord{}, newError(ErrorServerError, 500, "GrantType is not one of Config.AdditionalGrantTypes", nil)
	case req.Client.instanceKey == "" || req.Client.authenticatedID != client.ID():
		return grantRecord{}, newError(ErrorServerError, 500, "Client must be as AuthenticateAttestedClient returned it", nil)
	case req.Binding.Thumbprint == "" || req.Binding.SenderConstrain != client.SenderConstrain():
		return grantRecord{}, newError(ErrorServerError, 500, "Binding must name a credential of the client's registered sender constraint", nil)
	case req.Subject.String() == "":
		return grantRecord{}, newError(ErrorServerError, 500, "Subject is required", nil)
	case len(req.Scope) == 0 && len(req.AuthorizationDetails) == 0:
		return grantRecord{}, newError(ErrorServerError, 500, "Scope or AuthorizationDetails is required", nil)
	}
	for _, scope := range req.Scope {
		if scope == "openid" {
			return grantRecord{}, newError(ErrorInvalidScope, 400, "openid can't be granted without an authenticated user", nil)
		}
		if !s.clientAllowsScope(client, scope) {
			return grantRecord{}, newError(ErrorInvalidScope, 400, "scope is not valid for this client", nil)
		}
	}
	details, detailsErr := s.embedderAuthorizationDetails(req)
	if detailsErr != nil {
		return grantRecord{}, detailsErr
	}
	if err := s.validateGrantID(req.GrantID); err != nil {
		return grantRecord{}, newError(ErrorServerError, 500, "GrantID is invalid", err)
	}
	return grantRecord{
		Subject:              req.Subject.String(),
		Scope:                slices.Clone(req.Scope),
		AuthorizationDetails: details,
		GrantID:              req.GrantID,
	}, nil
}

// embedderAuthorizationDetails validates req's authorization details
// under Config.RAR and the client's registered types, returning them as
// one JSON array, or nil when there are none.
func (s *Server) embedderAuthorizationDetails(req IssueRefreshTokenRequest) (json.RawMessage, *Error) {
	if len(req.AuthorizationDetails) == 0 {
		return nil, nil
	}
	if s.cfg.RAR == nil {
		return nil, newError(ErrorInvalidAuthorizationDetails, 400, "authorization_details is not supported by this server", nil)
	}
	raw, _ := json.Marshal(req.AuthorizationDetails) // marshaling a []json.RawMessage cannot fail
	if _, err := s.cfg.RAR.Parse(raw); err != nil {
		return nil, newError(ErrorInvalidAuthorizationDetails, 400, "authorization_details is invalid", err)
	}
	if err := checkAuthorizationDetailsTypes(req.Client.Client, req.AuthorizationDetails); err != nil {
		return nil, newError(ErrorInvalidAuthorizationDetails, 400, "authorization_details is not permitted for this client", err)
	}
	return raw, nil
}

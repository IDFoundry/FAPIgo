package server

import (
	"context"
	"crypto/x509"
	"strings"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/storage"
)

// ClientCredentialsTokenRequest is the input to
// Server.RequestClientCredentialsToken.
type ClientCredentialsTokenRequest struct {
	HTTP FormRequest

	// DPoPProof is the value of the request's DPoP header — required
	// when the authenticated client's storage.RegisteredClient.SenderConstrain()
	// is SenderConstrainDPoP (the default). Same shape as
	// AuthorizationCodeExchangeRequest.DPoPProof.
	DPoPProof string

	// PeerCertificate is the TLS client certificate presented on the
	// connection this request arrived on, if any — required instead of
	// DPoPProof when the authenticated client's SenderConstrain() is
	// SenderConstrainMTLS (RFC 8705 §3). Same shape as
	// AuthorizationCodeExchangeRequest.PeerCertificate.
	PeerCertificate *x509.Certificate
}

// RequestClientCredentialsToken implements the RFC 6749 §4.4
// client_credentials grant: authenticates the client, verifies its
// sender-constraining binding, and issues an access token scoped to
// whatever subset of the client's own registered scopes it explicitly
// requests. There is no authorization code to redeem and no end user —
// no ID token, no refresh token (RFC 6749 §4.4.3 says a refresh token
// "SHOULD NOT" be included), no PAR/redirect_uri/PKCE at all. Disabled
// entirely unless both Config.ClientCredentialsGrant is set and the
// authenticated client's own AllowsClientCredentialsGrant() is true —
// see both fields' own doc comments for why this needs two separate
// opt-ins, not one.
func (s *Server) RequestClientCredentialsToken(ctx context.Context, req ClientCredentialsTokenRequest) (TokenResult, error) {
	if !s.cfg.ClientCredentialsGrant {
		return s.tokenFail(ctx, AuditEventRequestClientCredentialsToken, "", newError(ErrorUnsupportedGrantType, 400, "the client_credentials grant is not enabled on this server", nil))
	}

	params, err := formParametersToMap(req.HTTP.Parameters)
	if err != nil {
		return s.tokenFail(ctx, AuditEventRequestClientCredentialsToken, "", newError(ErrorInvalidRequest, 400, "the request contains a duplicated parameter", err))
	}

	if params["grant_type"] != "client_credentials" {
		return s.tokenFail(ctx, AuditEventRequestClientCredentialsToken, "", newError(ErrorUnsupportedGrantType, 400, "grant_type must be client_credentials", nil))
	}

	client, _, authErr := s.authenticateClient(ctx, params, req.PeerCertificate, []fapi.URL{s.cfg.Endpoints.Token}, []fapi.URL{s.cfg.MTLSEndpoints.Token})
	if authErr != nil {
		return s.tokenFail(ctx, AuditEventRequestClientCredentialsToken, "", authErr)
	}
	if !client.AllowsClientCredentialsGrant() {
		return s.tokenFail(ctx, AuditEventRequestClientCredentialsToken, client.ID(), newError(ErrorUnauthorizedClient, 400, "this client is not registered for the client_credentials grant", nil))
	}

	scopeTokens := strings.Fields(params["scope"])
	if len(scopeTokens) == 0 {
		return s.tokenFail(ctx, AuditEventRequestClientCredentialsToken, client.ID(), newError(ErrorInvalidScope, 400, "scope is required", nil))
	}
	for _, tok := range scopeTokens {
		if !client.AllowsScope(tok) {
			return s.tokenFail(ctx, AuditEventRequestClientCredentialsToken, client.ID(), newError(ErrorInvalidScope, 400, "scope is not valid for this client", nil))
		}
	}

	thumbprint, bindingErr := s.verifyTokenRequestBinding(ctx, client, req.DPoPProof, req.PeerCertificate)
	if bindingErr != nil {
		return s.tokenFail(ctx, AuditEventRequestClientCredentialsToken, client.ID(), bindingErr)
	}

	now := s.deps.Clock.Now()
	// The client is its own subject: RFC 9068 §2.2 requires a "sub"
	// claim, and there is no end user for this grant to name instead —
	// the client_id is the only identity a client_credentials token can
	// meaningfully assert, the same convention RFC 6749 §4.4's own
	// "resource owner" concept collapses into "the client" for this
	// grant.
	// The returned revocation-lookup key is discarded, not recorded:
	// storage.GrantStore.RecordIssuedAccessToken exists specifically to
	// associate an issuance with the authorization code it came from,
	// so a *second* redemption of that same code can revoke the first
	// issuance (RFC 6749 §4.1.2). There is no code (or any other
	// redeemable grant) here to ever be replayed against.
	accessToken, _, err := s.deps.AccessTokens.IssueAccessToken(ctx, AccessTokenParams{
		ClientID: client.ID(), Subject: client.ID().String(), Scope: scopeTokens,
		Thumbprint: thumbprint, SenderConstrain: client.SenderConstrain(),
		Issuer: s.cfg.Issuer.String(), Audience: s.cfg.Issuer.String(),
		Now: now, Lifetime: s.cfg.Limits.AccessTokenLifetime, Random: s.deps.Random,
	})
	if err != nil {
		return s.tokenFail(ctx, AuditEventRequestClientCredentialsToken, client.ID(), newError(ErrorServerError, 500, "failed to issue access token", err))
	}

	result := TokenResult{
		AccessToken: fapi.NewSecret(accessToken),
		TokenType:   tokenTypeFor(client.SenderConstrain()),
		ExpiresIn:   s.cfg.Limits.AccessTokenLifetime,
		Scope:       strings.Join(scopeTokens, " "),
	}

	if s.deps.Nonces != nil && client.SenderConstrain() == storage.SenderConstrainDPoP {
		nextNonce, err := s.issueDPoPNonce(ctx, now)
		if err != nil {
			return s.tokenFail(ctx, AuditEventRequestClientCredentialsToken, client.ID(), newError(ErrorServerError, 500, "failed to issue dpop nonce", err))
		}
		result.NextDPoPNonce = nextNonce
	}

	s.audit(ctx, AuditEventRequestClientCredentialsToken, client.ID(), AuditOutcomeSuccess, "")
	return result, nil
}

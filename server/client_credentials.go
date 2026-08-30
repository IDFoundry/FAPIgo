package server

import (
	"context"
	"crypto/x509"
	"encoding/json"
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

// ClientCredentialsRARPolicy decides which of a client_credentials
// request's own Rich Authorization Requests (RFC 9396) detail objects an
// authenticated client is entitled to receive — the client_credentials
// analogue of a resource owner's GrantedAuthorization.AuthorizationDetails
// decision on PAR/CIBA, which this grant has no interactive consent step
// to produce on its own. RFC 9396 §6 frames this as "the client's
// policy," as distinct from PAR/CIBA's own "the underlying grant" check.
//
// Dependencies.ClientCredentialsRARPolicy is optional, but its absence
// is not permissive: a client_credentials request that names
// authorization_details with no policy configured is refused with
// ErrorInvalidAuthorizationDetails, the same "unconfigured is not the
// same as an empty registry accepting nothing extra" stance Config.RAR's
// own doc comment already takes for the server as a whole — every
// registered RAR type is available to be *requested* once Config.RAR is
// set, but nothing is ever *entitled* to be granted on this grant
// without an explicit policy decision saying so.
type ClientCredentialsRARPolicy interface {
	// Authorize returns the subset of requested (each entry one of its
	// already-validated — RARRegistry.Parse has run — detail objects)
	// that clientID's own policy permits, narrowed or reordered however
	// the implementation decides; RequestClientCredentialsToken checks
	// the result is an acceptable narrowing of requested the same way
	// validateGrantedAuthorizationDetails already checks a resource
	// owner's own decision (RARDefinition.ValidateGrant, or exact-match
	// if that hook is nil for a given type). Returning an empty granted
	// (no error) is a legitimate "deny everything requested" decision —
	// RequestClientCredentialsToken surfaces that as
	// ErrorInvalidAuthorizationDetails itself, per RFC 9396 §6's own
	// "the AS refuses the request" framing, so an implementation doesn't
	// need to return an error just to express a full denial. Returning
	// an error instead signals a policy-evaluation failure (a lookup
	// error, an unreachable policy engine) — also surfaced as
	// ErrorInvalidAuthorizationDetails, since the caller cannot tell the
	// two apart from the client-visible response.
	Authorize(ctx context.Context, clientID fapi.ClientID, requested []json.RawMessage) ([]json.RawMessage, error)
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
//
// Also accepts an "authorization_details" (RFC 9396 §6) token request
// parameter when Config.RAR is configured — structurally validated
// against Config.RAR, then checked against Dependencies.ClientCredentialsRARPolicy
// (RFC 9396 §6's "client's policy"), since this grant has no resource
// owner of its own to make that decision interactively the way PAR/CIBA
// do. See ClientCredentialsRARPolicy's own doc comment for the exact
// contract, including what an unconfigured policy means.
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

	// RFC 9396 §6: for client_credentials, "the AS checks whether ...
	// the client's policy ... allows the issuance of an access token
	// with the requested authorization details." Structural validation
	// (registered type, bounds, shape) happens first, exactly like
	// PAR/CIBA's own parseRequestedAuthorizationDetails call; the actual
	// entitlement decision then comes from
	// Dependencies.ClientCredentialsRARPolicy, since this grant has no
	// resource owner to make it interactively the way PAR/CIBA's own
	// validateGrantedAuthorizationDetails step does.
	authorizationDetailsRequested, err := s.parseRequestedAuthorizationDetails(plainParamsToJSON(params))
	if err != nil {
		return s.tokenFail(ctx, AuditEventRequestClientCredentialsToken, client.ID(), newError(ErrorInvalidAuthorizationDetails, 400, "authorization_details is invalid", err))
	}
	var authorizationDetails json.RawMessage
	if len(authorizationDetailsRequested) > 0 {
		if s.deps.ClientCredentialsRARPolicy == nil {
			return s.tokenFail(ctx, AuditEventRequestClientCredentialsToken, client.ID(), newError(ErrorInvalidAuthorizationDetails, 400, "this server has no client_credentials authorization_details policy configured", nil))
		}
		var requestedObjects []json.RawMessage
		if unmarshalErr := json.Unmarshal(authorizationDetailsRequested, &requestedObjects); unmarshalErr != nil {
			return s.tokenFail(ctx, AuditEventRequestClientCredentialsToken, client.ID(), newError(ErrorServerError, 500, "failed to decode validated authorization_details", unmarshalErr))
		}
		granted, policyErr := s.deps.ClientCredentialsRARPolicy.Authorize(ctx, client.ID(), requestedObjects)
		if policyErr != nil {
			return s.tokenFail(ctx, AuditEventRequestClientCredentialsToken, client.ID(), newError(ErrorInvalidAuthorizationDetails, 400, "authorization_details is not permitted by this client's policy", policyErr))
		}
		if len(granted) == 0 {
			return s.tokenFail(ctx, AuditEventRequestClientCredentialsToken, client.ID(), newError(ErrorInvalidAuthorizationDetails, 400, "this client's policy does not permit any of the requested authorization_details", nil))
		}
		validated, validateErr := s.validateGrantedAuthorizationDetails(authorizationDetailsRequested, granted)
		if validateErr != nil {
			return s.tokenFail(ctx, AuditEventRequestClientCredentialsToken, client.ID(), newError(ErrorInvalidAuthorizationDetails, 400, "authorization_details policy decision is not an acceptable narrowing of the request", validateErr))
		}
		authorizationDetails = validated
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
	accessTokenClaims := withAuthorizationDetails(authorizationDetails, nil)
	accessToken, _, err := s.deps.AccessTokens.IssueAccessToken(ctx, AccessTokenParams{
		ClientID: client.ID(), Subject: client.ID().String(), Scope: scopeTokens,
		Thumbprint: thumbprint, SenderConstrain: client.SenderConstrain(), Claims: accessTokenClaims,
		Issuer: s.cfg.Issuer.String(), Audience: s.cfg.Issuer.String(),
		Now: now, Lifetime: s.cfg.Limits.AccessTokenLifetime, Random: s.deps.Random,
	})
	if err != nil {
		return s.tokenFail(ctx, AuditEventRequestClientCredentialsToken, client.ID(), newError(ErrorServerError, 500, "failed to issue access token", err))
	}

	result := TokenResult{
		AccessToken:          fapi.NewSecret(accessToken),
		TokenType:            tokenTypeFor(client.SenderConstrain()),
		ExpiresIn:            s.cfg.Limits.AccessTokenLifetime,
		Scope:                strings.Join(scopeTokens, " "),
		AuthorizationDetails: authorizationDetails,
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

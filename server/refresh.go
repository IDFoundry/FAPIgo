package server

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"strings"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/storage"
)

// RefreshTokenRequest is the input to Server.RefreshAccessToken.
type RefreshTokenRequest struct {
	HTTP FormRequest

	// DPoPProofs is every "DPoP" header value the request carried, in
	// receipt order — see AuthorizationCodeExchangeRequest.DPoPProofs'
	// own doc comment for why this is a slice, not a single string.
	// Required (exactly one value) when the authenticated client's
	// SenderConstrain() is SenderConstrainDPoP (the default). It must
	// be a valid, fresh proof, but — since every client this server
	// accepts is confidential (private_key_jwt client authentication is
	// always required; there is no public-client path) — it need not
	// be bound to the same key the refresh token was originally issued
	// to. RFC 9449 §5: "Refresh tokens issued to confidential
	// clients... are not bound to the DPoP proof public key because
	// they are already sender-constrained with a different existing
	// mechanism [client authentication]." The newly issued access token
	// is bound to whichever key this request presents, so a client
	// rotating its DPoP key at refresh time is expected and correctly
	// handled, not an error.
	DPoPProofs []string

	// ClientAttestations/ClientAttestationPoPs mirror
	// AuthorizationCodeExchangeRequest's own fields — see its doc
	// comment. draft-ietf-oauth-attestation-based-client-auth-07 §10.3
	// binds a refresh token issued to a client authenticated this way
	// to its Client Instance Key: a refresh must present an attestation
	// whose cnf key is the one presented when the token was issued, or
	// it fails with invalid_grant. Every installation of a wallet app
	// shares one client_id, so this is what stops one installation
	// redeeming another's refresh token.
	ClientAttestations    []string
	ClientAttestationPoPs []string

	// PeerCertificate is the TLS client certificate presented on the
	// connection this request arrived on, if any — required instead of
	// a DPoP proof when the authenticated client's SenderConstrain() is
	// SenderConstrainMTLS. Mirrors DPoPProofs' own "whichever credential
	// shows up wins" reasoning: an mTLS-bound client rotating its
	// certificate at refresh time is expected and correctly handled the
	// same way.
	PeerCertificate *x509.Certificate
}

// RefreshAccessToken authenticates the client, verifies its DPoP proof,
// and redeems the refresh token to issue a new access token (and ID
// token, if the granted scope includes openid). It does not rotate the
// refresh token: FAPI2-SP-FINAL requirement 5.3.2.1-9 says an
// authorization server "shall not use refresh token rotation except in
// extraordinary circumstances", so the presented token is returned
// unchanged in the response and remains valid for the caller's next
// refresh too — see storage.GrantStore.RedeemRefreshToken's doc
// comment. A requested scope may narrow, but never widen, the token's
// original grant.
//
// The grant is checked against the client's current registration, not
// only the one it was issued under: a scope the client may no longer use
// (removed from AllowedScopes, or openid under Config.OAuthOnly) is
// refused with invalid_scope, and the client can still refresh by
// requesting a narrower scope without it; authorization_details of a
// type the client or Config.RAR no longer allows are refused with
// invalid_grant, and the client must authorize again.
func (s *Server) RefreshAccessToken(ctx context.Context, req RefreshTokenRequest) (TokenResult, error) {
	params, err := formParametersToMap(req.HTTP.Parameters)
	if err != nil {
		return s.tokenFail(ctx, AuditEventRefreshAccessToken, "", newError(ErrorInvalidRequest, 400, "the request's parameters are duplicated, too many, or too large", err))
	}
	if params["grant_type"] != "refresh_token" {
		return s.tokenFail(ctx, AuditEventRefreshAccessToken, "", newError(ErrorUnsupportedGrantType, 400, "grant_type must be refresh_token", nil))
	}

	client, dpopProof, authn, authErr := s.authenticateRequest(ctx, params, requestCredentials{
		PeerCertificate: req.PeerCertificate, DPoPProofs: req.DPoPProofs, ClientAttestations: req.ClientAttestations, ClientAttestationPoPs: req.ClientAttestationPoPs,
	}, []fapi.URL{s.cfg.Endpoints.Token}, []fapi.URL{s.cfg.MTLSEndpoints.Token})
	if authErr != nil {
		return s.tokenFail(ctx, AuditEventRefreshAccessToken, "", authErr)
	}

	rawToken := params["refresh_token"]
	if rawToken == "" {
		return s.tokenFail(ctx, AuditEventRefreshAccessToken, client.ID(), newError(ErrorInvalidRequest, 400, "refresh_token is required", nil))
	}

	thumbprint, bindingErr := s.verifyTokenRequestBinding(ctx, client, dpopProof, req.PeerCertificate)
	if bindingErr != nil {
		return s.tokenFail(ctx, AuditEventRefreshAccessToken, client.ID(), bindingErr)
	}

	grant, now, grantErr := s.redeemRefreshGrant(ctx, client.ID(), authn.InstanceKey, rawToken)
	if grantErr != nil {
		return s.tokenFail(ctx, AuditEventRefreshAccessToken, client.ID(), grantErr)
	}
	// No DPoP-key match check against grant.Thumbprint here — see
	// RefreshTokenRequest.DPoPProofs' doc comment. client.ID() above is
	// only ever reached via successful client_assertion verification
	// (authenticateClient), so every caller here is confidential; RFC
	// 9449 §5 does not bind a confidential client's refresh token to a
	// specific DPoP key at all.

	scope, scopeErr := refreshScope(params, grant)
	if scopeErr != nil {
		return s.tokenFail(ctx, AuditEventRefreshAccessToken, client.ID(), scopeErr)
	}
	if allowedErr := s.checkGrantStillAllowed(client, scope, grant.AuthorizationDetails); allowedErr != nil {
		return s.tokenFail(ctx, AuditEventRefreshAccessToken, client.ID(), allowedErr)
	}

	accessTokenClaims, err := grant.accessTokenClaims()
	if err != nil {
		return s.tokenFail(ctx, AuditEventRefreshAccessToken, client.ID(), newError(ErrorServerError, 500, "failed to encode requested userinfo claims", err))
	}
	// Revocation-lookup key discarded — refresh-token redemption is
	// deliberately not single-use (FAPI2-SP-FINAL 5.3.2.1-9), so
	// there's no "reuse" event on this path to revoke an access token
	// against; that tracking is specific to authorization-code reuse
	// (see ExchangeAuthorizationCode).
	accessToken, _, err := s.deps.AccessTokens.IssueAccessToken(ctx, AccessTokenParams{
		ClientID: client.ID(), Subject: grant.Subject, Scope: scope,
		Thumbprint: thumbprint, SenderConstrain: client.SenderConstrain(), Claims: accessTokenClaims,
		Issuer: s.cfg.Issuer.String(), Audience: s.cfg.Issuer.String(),
		Now: now, Lifetime: s.cfg.Limits.AccessTokenLifetime, Random: s.deps.Random,
	})
	if err != nil {
		return s.tokenFail(ctx, AuditEventRefreshAccessToken, client.ID(), newError(ErrorServerError, 500, "failed to issue access token", err))
	}

	result := TokenResult{
		AccessToken:          fapi.NewSecret(accessToken),
		TokenType:            tokenTypeFor(client.SenderConstrain()),
		ExpiresIn:            s.cfg.Limits.AccessTokenLifetime,
		Scope:                strings.Join(scope, " "),
		AuthorizationDetails: grant.AuthorizationDetails,
	}

	if containsScope(scope, "openid") {
		// A refreshed ID token omits nonce — it was only ever meant to
		// bind the *original* ID token to the authorization request that
		// requested it, not to every subsequent refresh.
		idToken, idErr := s.issueIDTokenForGrant(ctx, client, grant, "", accessToken)
		if idErr != nil {
			return s.tokenFail(ctx, AuditEventRefreshAccessToken, client.ID(), idErr)
		}
		result.IDToken = fapi.NewSecret(idToken)
		result.HasIDToken = true
	}

	// The refresh token is not rotated — see this function's doc
	// comment — so the response simply echoes back the same value the
	// client presented, rather than minting and persisting a new one.
	result.RefreshToken = fapi.NewSecret(rawToken)
	result.HasRefreshToken = true

	if nonceErr := s.addNextDPoPNonce(ctx, client, now, &result); nonceErr != nil {
		return s.tokenFail(ctx, AuditEventRefreshAccessToken, client.ID(), nonceErr)
	}

	s.audit(ctx, AuditEventRefreshAccessToken, client.ID(), AuditOutcomeSuccess, "")
	return result, nil
}

// redeemRefreshGrant looks up the grant rawToken, a refresh token
// presented by clientID, was issued from, refusing one that has expired,
// was issued to another client or another client instance, or whose
// grant was revoked. It also returns the time it judged expiry at.
//
// instanceKey is the presenting client's Client Instance Key thumbprint
// (empty unless it authenticated by Client Attestation). A grant bound
// to an instance key is redeemed only with that key (draft-07 §10.3):
// every installation of a wallet app shares one client_id, so client_id
// alone would let one installation use another's refresh token.
func (s *Server) redeemRefreshGrant(ctx context.Context, clientID fapi.ClientID, instanceKey, rawToken string) (grantRecord, time.Time, *Error) {
	redeemed, err := s.deps.Grants.RedeemRefreshToken(ctx, storage.RefreshTokenRedemption{
		TokenHash: sha256.Sum256([]byte(rawToken)),
	})
	if err != nil {
		return grantRecord{}, time.Time{}, newError(ErrorInvalidGrant, 400, "refresh_token is invalid, expired, or already used", err)
	}

	now := s.deps.Clock.Now()
	if !now.Before(redeemed.ExpiresAt) {
		return grantRecord{}, time.Time{}, newError(ErrorInvalidGrant, 400, "refresh_token has expired", nil)
	}
	if redeemed.ClientID != clientID {
		return grantRecord{}, time.Time{}, newError(ErrorInvalidGrant, 400, "refresh_token was not issued to this client", nil)
	}
	grant, err := decodeGrantRecord(redeemed.Grant)
	if err != nil {
		return grantRecord{}, time.Time{}, newError(ErrorServerError, 500, "failed to decode refresh token grant", err)
	}
	if grant.ClientInstanceKey != "" && grant.ClientInstanceKey != instanceKey {
		return grantRecord{}, time.Time{}, newError(ErrorInvalidGrant, 400, "refresh_token was issued to another client instance", nil)
	}
	if revErr := s.checkGrantNotRevoked(ctx, grant); revErr != nil {
		return grantRecord{}, time.Time{}, revErr
	}
	return grant, now, nil
}

// checkGrantStillAllowed refuses to issue tokens for scope and
// authorizationDetails that the client's current registration no longer
// allows. A grant was checked when it was made, but a registration can
// change afterwards: a scope removed from AllowedScopes, Config.OAuthOnly
// turned on, a Rich Authorization Request type removed from
// AuthorizationDetailsTypes or from Config.RAR, or a federation policy
// narrowing an automatically registered client.
//
// It refuses rather than narrowing silently. A scope fails with
// invalid_scope, and the client can still refresh by asking for a
// narrower scope that leaves it out. Authorization details have no
// refresh-time narrowing, so a type the client may no longer request
// fails with invalid_grant, and the client must authorize again.
func (s *Server) checkGrantStillAllowed(client storage.RegisteredClient, scope []string, authorizationDetails json.RawMessage) *Error {
	for _, sc := range scope {
		if !s.clientAllowsScope(client, sc) {
			return newError(ErrorInvalidScope, 400, "the grant includes a scope this client may no longer use", nil)
		}
	}
	if len(authorizationDetails) == 0 {
		return nil
	}
	if s.cfg.RAR == nil {
		return newError(ErrorInvalidGrant, 400, "the grant has authorization_details, which this server no longer supports", nil)
	}
	// Parse refuses a type Config.RAR no longer registers, and checks each
	// detail against the current definitions.
	if _, err := s.cfg.RAR.Parse(authorizationDetails); err != nil {
		return newError(ErrorInvalidGrant, 400, "the grant's authorization_details are no longer valid on this server", err)
	}
	var details []json.RawMessage
	if err := json.Unmarshal(authorizationDetails, &details); err != nil {
		return newError(ErrorServerError, 500, "failed to decode the grant's authorization_details", err)
	}
	if err := checkAuthorizationDetailsTypes(client, details); err != nil {
		return newError(ErrorInvalidGrant, 400, "the grant's authorization_details include a type this client may no longer request", err)
	}
	return nil
}

// checkGrantUsable is checkGrantNotRevoked and checkGrantStillAllowed
// together, for a grant issued in full (the CIBA token exchange).
func (s *Server) checkGrantUsable(ctx context.Context, client storage.RegisteredClient, grant grantRecord) *Error {
	if revErr := s.checkGrantNotRevoked(ctx, grant); revErr != nil {
		return revErr
	}
	return s.checkGrantStillAllowed(client, grant.Scope, grant.AuthorizationDetails)
}

// refreshScope is the scope a refresh request asks for: the grant's,
// or a narrower one named by its scope parameter, never a wider one.
func refreshScope(params map[string]string, grant grantRecord) ([]string, *Error) {
	requestedScope, ok := params["scope"]
	if !ok || requestedScope == "" {
		return grant.Scope, nil
	}
	narrowed := strings.Fields(requestedScope)
	if err := validateGrantedScopeSubset(narrowed, strings.Join(grant.Scope, " ")); err != nil {
		return nil, newError(ErrorInvalidScope, 400, "requested scope exceeds the original grant", err)
	}
	return narrowed, nil
}

package server

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"slices"
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
	// comment. draft-ietf-oauth-attestation-based-client-auth-12 §10.3
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

// RefreshAccessToken authenticates the client, verifies its
// sender-constraining binding (a DPoP proof or its mTLS certificate),
// and redeems the refresh token to issue a new access token (and ID
// token, if the granted scope includes openid). It does not rotate the
// refresh token: FAPI2-SP-FINAL requirement 5.3.2.1-11 says an
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
// invalid_grant, and the client must authorize again. A client no
// longer registered for the grant the refresh token came from — the
// authorization code grant, or CIBA — is refused with
// ErrorUnauthorizedClient, and so is a refresh token from
// IssueRefreshToken once its grant type is no longer one of
// Config.AdditionalGrantTypes. A refresh token whose grant type was
// never recorded (see checkGrantTypeStillAllowed) is refused with
// invalid_grant.
func (s *Server) RefreshAccessToken(ctx context.Context, req RefreshTokenRequest) (_ TokenResult, retErr error) {
	formParams, requestedResources := s.takeResourceParameters(req.HTTP.Parameters)
	params, err := formParametersToMap(formParams)
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
	// The proof's nonce, if any, is spent from here: see
	// attachNextDPoPNonceOnFailure.
	defer s.attachNextDPoPNonceOnFailure(ctx, client, &retErr)

	grant, now, grantErr := s.redeemRefreshGrantFor(ctx, client, authn.InstanceKey, rawToken)
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
	// The refresh token stays bound to all of the grant's resources,
	// whatever this access token is narrowed to (RFC 8707 §2.2).
	audience, audiences, allowedErr := s.allowedGrantAudience(ctx, client, grant, scope, requestedResources)
	if allowedErr != nil {
		return s.tokenFail(ctx, AuditEventRefreshAccessToken, client.ID(), allowedErr)
	}

	accessTokenClaims, err := grant.accessTokenClaims()
	if err != nil {
		return s.tokenFail(ctx, AuditEventRefreshAccessToken, client.ID(), newError(ErrorServerError, 500, "failed to encode requested userinfo claims", err))
	}
	// Revocation-lookup key discarded — refresh-token redemption is
	// deliberately not single-use (FAPI2-SP-FINAL 5.3.2.1-11), so
	// there's no "reuse" event on this path to revoke an access token
	// against; that tracking is specific to authorization-code reuse
	// (see ExchangeAuthorizationCode).
	sub, internal := grant.accessTokenSubjects()
	accessToken, _, err := s.deps.AccessTokens.IssueAccessToken(ctx, AccessTokenParams{
		ClientID: client.ID(), Subject: sub, InternalSubject: internal, Scope: scope,
		Thumbprint: thumbprint, SenderConstrain: client.SenderConstrain(), Claims: accessTokenClaims,
		Issuer: s.cfg.Issuer.String(), Audience: audience, Audiences: audiences,
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

// redeemRefreshGrantFor is redeemRefreshGrant for a refresh, which also
// refuses a grant from a grant type client is no longer registered for
// (checkGrantTypeStillAllowed). RevokeToken redeems without it: a client
// may still revoke what it can no longer refresh.
func (s *Server) redeemRefreshGrantFor(ctx context.Context, client storage.RegisteredClient, instanceKey, rawToken string) (grantRecord, time.Time, *Error) {
	grant, now, err := s.redeemRefreshGrant(ctx, client.ID(), instanceKey, rawToken)
	if err != nil {
		return grantRecord{}, time.Time{}, err
	}
	if typeErr := s.checkGrantTypeStillAllowed(client, grant); typeErr != nil {
		return grantRecord{}, time.Time{}, typeErr
	}
	return grant, now, nil
}

// checkGrantTypeStillAllowed refuses a refresh of a grant made under a
// grant type the client's current registration, or the server's
// configuration, no longer allows: an authorization code grant once the
// client has no redirect URI, a CIBA grant once it may no longer use
// CIBA — the same checks the authorization code exchange and the CIBA
// token exchange make — or a grant the embedder served
// (IssueRefreshToken) once its grant type is no longer one of
// Config.AdditionalGrantTypes.
//
// A grant without GrantType was recorded before it was: one with a
// CodeGrantID is an authorization code or CIBA grant and isn't checked,
// as before; one without is an embedder's (or a code grant from before
// CodeGrantID existed), whose grant type can't be known, so it's
// refused rather than refreshed past a grant type's removal.
func (s *Server) checkGrantTypeStillAllowed(client storage.RegisteredClient, grant grantRecord) *Error {
	switch grant.GrantType {
	case "authorization_code":
		if !client.AllowsAuthorizationCodeGrant() {
			return newError(ErrorUnauthorizedClient, 400, "the client is no longer registered for the authorization code grant", nil)
		}
	case CIBAGrantType:
		if _, permitted := client.BackchannelAuthenticationRequestAlgorithm(); !permitted {
			return newError(ErrorUnauthorizedClient, 400, "the client is no longer registered for CIBA", nil)
		}
	case "":
		if grant.CodeGrantID == "" {
			return newError(ErrorInvalidGrant, 400, "refresh_token was issued for a grant of unknown type: authorize again", nil)
		}
	default:
		if !slices.Contains(s.cfg.AdditionalGrantTypes, grant.GrantType) {
			return newError(ErrorUnauthorizedClient, 400, "the grant type is no longer served", nil)
		}
	}
	return nil
}

// refreshTokenUnknownDescription is the error_description of the
// invalid_grant for a refresh token this server doesn't know, doesn't
// own (Server.ownsRecord), or whose record isn't a refresh token's.
const refreshTokenUnknownDescription = "refresh_token is invalid, expired, or already used"

// redeemRefreshGrant looks up the grant rawToken, a refresh token
// presented by clientID, was issued from, refusing one that has expired,
// was issued to another client or another client instance, or whose
// grant was revoked. It also returns the time it judged expiry at.
//
// instanceKey is the presenting client's Client Instance Key thumbprint
// (empty unless it authenticated by Client Attestation); see
// checkRefreshInstance for how it must match the grant's.
func (s *Server) redeemRefreshGrant(ctx context.Context, clientID fapi.ClientID, instanceKey, rawToken string) (grantRecord, time.Time, *Error) {
	redeemed, err := s.deps.Grants.RedeemRefreshToken(ctx, storage.RefreshTokenRedemption{
		TokenHash: sha256.Sum256([]byte(rawToken)),
	})
	if err != nil {
		return grantRecord{}, time.Time{}, newError(ErrorInvalidGrant, 400, refreshTokenUnknownDescription, err)
	}

	now := s.deps.Clock.Now()
	if !now.Before(redeemed.ExpiresAt) {
		return grantRecord{}, time.Time{}, newError(ErrorInvalidGrant, 400, "refresh_token has expired", nil)
	}
	if redeemed.ClientID != clientID {
		return grantRecord{}, time.Time{}, newError(ErrorInvalidGrant, 400, "refresh_token was not issued to this client", nil)
	}
	grant, err := s.decodeOwnGrantRecord(redeemed.Grant)
	if err != nil {
		return grantRecord{}, time.Time{}, recordFailure(err, newError(ErrorInvalidGrant, 400, refreshTokenUnknownDescription, nil), "refresh token grant")
	}
	if !grant.isKind(grantKindRefreshToken) {
		// Another artefact's record — an authorization code's, from a
		// store keeping both in one table — is as unknown as no record.
		return grantRecord{}, time.Time{}, newError(ErrorInvalidGrant, 400, refreshTokenUnknownDescription, nil)
	}
	if !issuedWithin(grant.IssuedAt, s.cfg.Limits.RefreshTokenLifetime, now) {
		return grantRecord{}, time.Time{}, newError(ErrorInvalidGrant, 400, "refresh_token has expired", nil)
	}
	if instanceErr := checkRefreshInstance(grant, instanceKey); instanceErr != nil {
		return grantRecord{}, time.Time{}, instanceErr
	}
	if revErr := s.checkGrantNotRevoked(ctx, grant); revErr != nil {
		return grantRecord{}, time.Time{}, revErr
	}
	return grant, now, nil
}

// checkRefreshInstance refuses a refresh token presented by a Client
// Instance other than the one it was issued to. A grant bound to an
// instance key is redeemed only with that key (draft-12 §10.3): every
// installation of a wallet app shares one client_id, so client_id alone
// would let one installation use another's refresh token.
//
// The binding holds the other way too. A client registered for several
// authentication methods — a backend using private_key_jwt beside its
// app's installations using Client Attestation — has refresh tokens
// issued under its other methods with no instance key, and an attested
// installation mustn't redeem those: a backend's refresh token, if it
// leaked, would otherwise work for any genuine installation. Such a
// grant is told apart from one written before instance keys were
// recorded (v0.47.0), which stays redeemable, by its IssuedAt: recorded
// since v0.50.0, so a grant that has it but no instance key was issued
// under another method.
func checkRefreshInstance(grant grantRecord, instanceKey string) *Error {
	switch {
	case grant.ClientInstanceKey != "" && grant.ClientInstanceKey != instanceKey:
		return newError(ErrorInvalidGrant, 400, "refresh_token was issued to another client instance", nil)
	case grant.ClientInstanceKey == "" && instanceKey != "" && grant.IssuedAt != nil:
		return newError(ErrorInvalidGrant, 400, "refresh_token was not issued to a client instance", nil)
	}
	return nil
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
// fails with invalid_grant, and the client must authorize again. So
// does a grant issued with a public sub at a server that now issues only
// pairwise ones (see checkGrantSubjectStillIssued). scope is what the
// request asks for: the grant's own, or a narrower one at refresh. A
// grant's RFC 8707 resources are checked the same way scopes are, once
// the request has narrowed them (see narrowedAudience).
func (s *Server) checkGrantStillAllowed(client storage.RegisteredClient, grant grantRecord, scope []string) *Error {
	if subjectErr := s.checkGrantSubjectStillIssued(grant); subjectErr != nil {
		return subjectErr
	}
	authorizationDetails := grant.AuthorizationDetails
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

// checkGrantSubjectStillIssued refuses a grant whose sub this server can
// no longer stand behind. One made while its client got public subs,
// now that this server issues only pairwise ones
// (SubjectTypesPairwiseOnly, which promises every client pairwise subs):
// its tokens would otherwise keep carrying the user's internal subject.
// And one whose pairwise sub was issued under another Config.Subjects
// Prefix: a resource server strips the current prefix to look a sub up,
// so its tokens would no longer resolve. A grant keeps the sub it was
// issued with (OpenID Connect Core §12.2), so neither can be moved to a
// new sub; the client authorizes again instead. Under
// SubjectTypesPerClient a grant otherwise keeps its sub whatever the
// client's type or sector has since become.
func (s *Server) checkGrantSubjectStillIssued(grant grantRecord) *Error {
	subjects := effectiveSubjects(s.cfg)
	if grant.ClientSubject == "" {
		if subjects.Enforcement == SubjectTypesPairwiseOnly {
			return newError(ErrorInvalidGrant, 400, "the grant was issued with a public sub, and this server now issues only pairwise subs", nil)
		}
		return nil
	}
	if subjects.Prefix.IsSet() && grant.PairwisePrefix != subjects.Prefix.String() {
		return newError(ErrorInvalidGrant, 400, "the grant's pairwise sub was issued under another subjects.prefix, so its tokens would no longer resolve", nil)
	}
	return nil
}

// pairwisePrefixOf is the Prefix a grant whose pairwise sub was derived
// for sector records: cfg's, or "" for a public client (no sector).
func pairwisePrefixOf(cfg Config, sector string) string {
	if sector == "" {
		return ""
	}
	return effectiveSubjects(cfg).Prefix.String()
}

// checkGrantUsable is checkGrantNotRevoked and checkGrantStillAllowed
// together, for a grant issued in full (the CIBA token exchange), after
// refusing a decision older than the current
// Limits.BackchannelAuthenticationRequestLifetime (see
// grantRecord.IssuedAt).
func (s *Server) checkGrantUsable(ctx context.Context, client storage.RegisteredClient, grant grantRecord) *Error {
	if !issuedWithin(grant.IssuedAt, s.cfg.Limits.BackchannelAuthenticationRequestLifetime, s.deps.Clock.Now()) {
		return newError(ErrorExpiredToken, 400, "auth_req_id has expired", nil)
	}
	if revErr := s.checkGrantNotRevoked(ctx, grant); revErr != nil {
		return revErr
	}
	return s.checkGrantStillAllowed(client, grant, grant.Scope)
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

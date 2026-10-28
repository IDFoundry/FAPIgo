package server

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"strconv"
	"strings"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/grantrevocation"
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

	// DPoPProofs is every "DPoP" header value the request carried, in
	// receipt order — required (exactly one value) when the
	// authenticated client's SenderConstrain() is SenderConstrainDPoP
	// (the default), the same requirement
	// ExchangeAuthorizationCode/RefreshAccessToken already have.
	DPoPProofs []string

	// ClientAttestations/ClientAttestationPoPs mirror
	// AuthorizationCodeExchangeRequest's own fields — see its doc
	// comment.
	ClientAttestations    []string
	ClientAttestationPoPs []string

	// PeerCertificate is the TLS client certificate presented on the
	// connection this request arrived on, if any — required instead of
	// a DPoP proof when the authenticated client's SenderConstrain() is
	// SenderConstrainMTLS.
	PeerCertificate *x509.Certificate
}

// ExchangeBackchannelAuthentication authenticates the client, verifies
// its sender-constraining binding (a DPoP proof or its mTLS
// certificate), and polls the pending backchannel authentication
// request identified by auth_req_id: if no decision has been recorded
// yet, it fails with ErrorAuthorizationPending (or ErrorSlowDown when
// polled sooner than Limits.BackchannelAuthenticationPollInterval);
// once denied or the end user failed to authenticate, it fails with
// ErrorAccessDenied; once expired, with ErrorExpiredToken; once
// approved, it issues an access token bound to the client's DPoP key or
// mTLS certificate (plus an ID token when the granted scope included
// "openid" and a refresh token when it included "offline_access") —
// exactly once, mirroring ExchangeAuthorizationCode's single-issuance
// guarantee: a later poll fails with ErrorInvalidGrant. An auth_req_id
// issued to another client is refused with ErrorInvalidGrant; a store
// that honours storage.PollBackchannelAuthentication.ClientID refuses
// it without spending the approval. So is an auth_req_id presented by
// another client instance than the one that made the request (for a
// client authenticated by Client Attestation), or, when the request
// carried a dpop_jkt, with another DPoP key: to the store it is
// unknown, so the approval is never spent by such a poll and the
// right instance and key can still redeem it. An approved grant is checked
// against the client's current registration first, as
// RefreshAccessToken does: a scope or authorization_details type the
// client may no longer use is refused (invalid_scope, invalid_grant),
// and a client no longer registered for CIBA at all is refused with
// ErrorUnauthorizedClient before the request is polled.
func (s *Server) ExchangeBackchannelAuthentication(ctx context.Context, req BackchannelTokenExchangeRequest) (_ TokenResult, retErr error) {
	if s.deps.Backchannel == nil {
		// RFC 6749 §5.2: a server that doesn't do CIBA doesn't support
		// its grant type.
		return s.tokenFail(ctx, AuditEventExchangeBackchannelAuthentication, "", newError(ErrorUnsupportedGrantType, 400, "backchannel authentication is not configured", nil))
	}
	formParams, requestedResources := s.takeResourceParameters(req.HTTP.Parameters)
	params, err := formParametersToMap(formParams)
	if err != nil {
		return s.tokenFail(ctx, AuditEventExchangeBackchannelAuthentication, "", newError(ErrorInvalidRequest, 400, "the request's parameters are duplicated, too many, or too large", err))
	}
	if params["grant_type"] != CIBAGrantType {
		return s.tokenFail(ctx, AuditEventExchangeBackchannelAuthentication, "", newError(ErrorUnsupportedGrantType, 400, "grant_type must be "+CIBAGrantType, nil))
	}

	// CIBA's own token-polling step (CIBA §10.1) is a grant_type on the
	// physical token endpoint, not a separate endpoint of its own — see
	// CIBAGrantType's own doc comment — so this authenticates against
	// the Token endpoint's audiences, the same as
	// ExchangeAuthorizationCode/RefreshAccessToken. Only a CIBA-registered
	// client can hold an auth_req_id, and such a client keeps CIBA Core
	// §7.1's endpoint-URL audiences — see
	// acceptableClientAssertionAudiences.
	client, dpopProof, authn, authErr := s.authenticateRequest(ctx, params, requestCredentials{
		PeerCertificate: req.PeerCertificate, DPoPProofs: req.DPoPProofs, ClientAttestations: req.ClientAttestations, ClientAttestationPoPs: req.ClientAttestationPoPs,
	}, []fapi.URL{s.cfg.Endpoints.Token}, []fapi.URL{s.cfg.MTLSEndpoints.Token})
	if authErr != nil {
		return s.tokenFail(ctx, AuditEventExchangeBackchannelAuthentication, "", authErr)
	}

	authReqID, paramErr := backchannelTokenParameters(client, params)
	if paramErr != nil {
		return s.tokenFail(ctx, AuditEventExchangeBackchannelAuthentication, client.ID(), paramErr)
	}

	thumbprint, bindingErr := s.verifyTokenRequestBinding(ctx, client, dpopProof, req.PeerCertificate)
	if bindingErr != nil {
		return s.tokenFail(ctx, AuditEventExchangeBackchannelAuthentication, client.ID(), bindingErr)
	}
	// The proof's nonce, if any, is spent from here: see
	// attachNextDPoPNonceOnFailure.
	defer s.attachNextDPoPNonceOnFailure(ctx, client, &retErr)

	now := s.deps.Clock.Now()
	polled, authReqIDHash, err := s.pollBackchannelAuthentication(ctx, client, authReqID, authn.InstanceKey, thumbprint, now)
	if err != nil {
		return s.tokenFail(ctx, AuditEventExchangeBackchannelAuthentication, client.ID(), backchannelPollError(err))
	}

	grant, grantErr := s.approvedBackchannelGrant(polled, client.ID(), thumbprint, authn.InstanceKey)
	if grantErr != nil {
		return s.tokenFail(ctx, AuditEventExchangeBackchannelAuthentication, client.ID(), grantErr)
	}
	grant.CodeGrantID = s.backchannelGrantID(authReqIDHash)
	audience, audiences, usableErr := s.usableGrantAudience(ctx, client, grant, requestedResources)
	if usableErr != nil {
		return s.tokenFail(ctx, AuditEventExchangeBackchannelAuthentication, client.ID(), usableErr)
	}
	accessTokenClaims, err := grant.accessTokenClaims()
	if err != nil {
		return s.tokenFail(ctx, AuditEventExchangeBackchannelAuthentication, client.ID(), newError(ErrorServerError, 500, "failed to encode requested userinfo claims", err))
	}
	sub, internal := grant.accessTokenSubjects()
	accessToken, _, issueErr := s.issueAccessToken(ctx, AccessTokenParams{
		ClientID: client.ID(), Subject: sub, InternalSubject: internal, Scope: grant.Scope,
		Thumbprint: thumbprint, SenderConstrain: client.SenderConstrain(), Claims: accessTokenClaims,
		Issuer: s.cfg.Issuer.String(), Audience: audience, Audiences: audiences,
		Now: now, Lifetime: s.cfg.Limits.AccessTokenLifetime, Random: s.deps.Random,
	})
	if issueErr != nil {
		return s.tokenFail(ctx, AuditEventExchangeBackchannelAuthentication, client.ID(), issueErr)
	}

	result := TokenResult{
		AccessToken:          fapi.NewSecret(accessToken),
		TokenType:            tokenTypeFor(client.SenderConstrain()),
		ExpiresIn:            s.cfg.Limits.AccessTokenLifetime,
		Scope:                strings.Join(grant.Scope, " "),
		AuthorizationDetails: grant.AuthorizationDetails,
	}

	if issueErr := s.issueBackchannelOptionalTokens(ctx, client, grant, accessToken, refreshBinding{Thumbprint: thumbprint, InstanceKey: authn.InstanceKey}, &result); issueErr != nil {
		return s.tokenFail(ctx, AuditEventExchangeBackchannelAuthentication, client.ID(), issueErr)
	}

	if nonceErr := s.addNextDPoPNonce(ctx, client, now, &result); nonceErr != nil {
		return s.tokenFail(ctx, AuditEventExchangeBackchannelAuthentication, client.ID(), nonceErr)
	}

	s.audit(ctx, AuditEventExchangeBackchannelAuthentication, client.ID(), AuditOutcomeSuccess, "")
	return result, nil
}

// backchannelTokenParameters returns the auth_req_id a CIBA token
// request must carry, once client is still registered for CIBA: the
// registration may have changed since the request was made, as at the
// authorization code exchange and refresh. Checked before polling, so an
// approval refused this way isn't spent.
func backchannelTokenParameters(client storage.RegisteredClient, params map[string]string) (string, *Error) {
	if _, permitted := client.BackchannelAuthenticationRequestAlgorithm(); !permitted {
		return "", newError(ErrorUnauthorizedClient, 400, "the client is no longer registered for CIBA", nil)
	}
	authReqID := params["auth_req_id"]
	if authReqID == "" {
		return "", newError(ErrorInvalidRequest, 400, "auth_req_id is required", nil)
	}
	return authReqID, nil
}

// backchannelAuthReqIDHashPrefix separates the digest of an auth_req_id
// bound to a client instance or a DPoP key from the plain SHA-256 of an
// unbound one.
const backchannelAuthReqIDHashPrefix = "fapigo bound auth_req_id\x00"

// backchannelAuthReqIDHash is the digest a CIBA request is stored and
// polled under (storage.NewBackchannelAuthentication.AuthReqIDHash):
// the plain SHA-256 of authReqID for a request bound to neither a
// client instance nor a DPoP key, as before such bindings existed, and
// otherwise the SHA-256 of authReqID bound to instanceKey (the
// thumbprint of the Client Instance Key of a client authenticated by
// Client Attestation) and dpopJKT (the request's dpop_jkt).
//
// The store spends an approval in the poll that observes it, before the
// server can compare the poll's client instance or DPoP key with the
// request's, and every installation of a wallet app shares one
// client_id. Keyed by both, an auth_req_id presented by another
// instance, or with another DPoP key, is simply unknown to the store,
// as authorizationCodeHash makes another instance's code: the poll
// neither spends the approval nor sees the request, so the poll from
// the instance and key it was issued to still succeeds. Each part is
// length-prefixed, so no two different bindings share a digest.
func backchannelAuthReqIDHash(authReqID, instanceKey, dpopJKT string) [32]byte {
	if instanceKey == "" && dpopJKT == "" {
		return sha256.Sum256([]byte(authReqID))
	}
	return sha256.Sum256([]byte(backchannelAuthReqIDHashPrefix +
		strconv.Itoa(len(instanceKey)) + ":" + instanceKey +
		strconv.Itoa(len(dpopJKT)) + ":" + dpopJKT + authReqID))
}

// pollBackchannelAuthentication polls the CIBA request authReqID names
// for client, presented by the client instance instanceKey with the
// DPoP or mTLS binding thumbprint, returning it and the digest it is
// stored under. A request with a dpop_jkt is stored under that key
// (backchannelAuthReqIDHash), so it is looked for under the presented
// DPoP key first, then under none, without the dpop_jkt it may not
// have. A miss leaves the store unchanged, so the second lookup is
// polled as if it were the only one.
func (s *Server) pollBackchannelAuthentication(ctx context.Context, client storage.RegisteredClient, authReqID, instanceKey, thumbprint string, now time.Time) (storage.PolledBackchannelAuthentication, [32]byte, error) {
	poll := func(hash [32]byte) (storage.PolledBackchannelAuthentication, error) {
		return s.deps.Backchannel.PollBackchannelAuthentication(ctx, storage.PollBackchannelAuthentication{
			AuthReqIDHash: hash,
			Now:           now,
			ClientID:      client.ID(),
		})
	}
	if client.SenderConstrain() != storage.SenderConstrainMTLS {
		hash := backchannelAuthReqIDHash(authReqID, instanceKey, thumbprint)
		polled, err := poll(hash)
		if err == nil || isBackchannelPollOutcome(err) {
			return polled, hash, err
		}
	}
	hash := backchannelAuthReqIDHash(authReqID, instanceKey, "")
	polled, err := poll(hash)
	return polled, hash, err
}

// isBackchannelPollOutcome reports whether err is one of the typed
// errors PollBackchannelAuthentication returns for a request it found,
// rather than one it doesn't know.
func isBackchannelPollOutcome(err error) bool {
	var expired *storage.BackchannelAuthenticationExpiredError
	var slowDown *storage.BackchannelAuthenticationSlowDownError
	var alreadyRedeemed *storage.BackchannelAuthenticationAlreadyRedeemedError
	return errors.As(err, &expired) || errors.As(err, &slowDown) || errors.As(err, &alreadyRedeemed)
}

// approvedBackchannelGrant returns the grant polled holds for clientID,
// whose DPoP or mTLS binding is thumbprint, presented by the client
// instance instanceKey, once it is approved: the auth_req_id must have
// been issued to clientID, by this server (ownsRecord), to that client
// instance, to the dpop_jkt it was bound to, if any.
// backchannelAuthReqIDHash already keeps another instance or DPoP key
// from finding the request at all; the record says the same.
func (s *Server) approvedBackchannelGrant(polled storage.PolledBackchannelAuthentication, clientID fapi.ClientID, thumbprint, instanceKey string) (grantRecord, *Error) {
	if polled.ClientID != clientID {
		return grantRecord{}, newError(ErrorInvalidGrant, 400, "auth_req_id was not issued to this client", nil)
	}
	request, err := s.decodeOwnRequestRecord(polled.Request)
	if err != nil {
		return grantRecord{}, recordFailure(err, newError(ErrorInvalidGrant, 400, authReqIDUnknownDescription, nil), "backchannel authentication request")
	}
	if request.ClientInstanceKey != instanceKey {
		return grantRecord{}, newError(ErrorInvalidGrant, 400, authReqIDUnknownDescription, nil)
	}
	if request.DPoPJKT != "" && request.DPoPJKT != thumbprint {
		return grantRecord{}, newError(ErrorInvalidGrant, 400, "DPoP proof key does not match the dpop_jkt bound to this backchannel authentication request", nil)
	}
	if statusErr := backchannelStatusError(polled.Status); statusErr != nil {
		return grantRecord{}, statusErr
	}
	grant, err := s.decodeOwnGrantRecord(polled.Grant)
	if err != nil {
		return grantRecord{}, recordFailure(err, newError(ErrorInvalidGrant, 400, authReqIDUnknownDescription, nil), "backchannel authentication grant")
	}
	if !grant.isKind(grantKindBackchannel) {
		return grantRecord{}, newError(ErrorInvalidGrant, 400, authReqIDUnknownDescription, nil)
	}
	return grant, nil
}

// authReqIDUnknownDescription is the error_description of the
// invalid_grant for an auth_req_id this server doesn't know, or doesn't
// own (Server.ownsRecord).
const authReqIDUnknownDescription = "auth_req_id is invalid or unknown"

// backchannelPollError is the token endpoint's answer when polling the
// backchannel authentication request fails with err.
func backchannelPollError(err error) *Error {
	var expired *storage.BackchannelAuthenticationExpiredError
	if errors.As(err, &expired) {
		return newError(ErrorExpiredToken, 400, "auth_req_id has expired", err)
	}
	var slowDown *storage.BackchannelAuthenticationSlowDownError
	if errors.As(err, &slowDown) {
		return newError(ErrorSlowDown, 400, "polled faster than the configured interval", err)
	}
	var alreadyRedeemed *storage.BackchannelAuthenticationAlreadyRedeemedError
	if errors.As(err, &alreadyRedeemed) {
		return newError(ErrorInvalidGrant, 400, "auth_req_id has already been used", err)
	}
	return newError(ErrorInvalidGrant, 400, authReqIDUnknownDescription, err)
}

// backchannelStatusError is the token endpoint's answer for a polled
// request in status, or nil once it's approved and tokens can be issued.
func backchannelStatusError(status storage.BackchannelAuthenticationStatus) *Error {
	switch status {
	case storage.BackchannelAuthenticationPending:
		return newError(ErrorAuthorizationPending, 400, "the end user has not yet completed authentication", nil)
	case storage.BackchannelAuthenticationDenied, storage.BackchannelAuthenticationAuthenticationFailed:
		return newError(ErrorAccessDenied, 400, "the end user denied the request, or could not be authenticated", nil)
	case storage.BackchannelAuthenticationApproved:
		return nil
	default:
		return newError(ErrorServerError, 500, "unrecognized backchannel authentication status", nil)
	}
}

// issueBackchannelOptionalTokens issues an ID token when grant's scope
// includes "openid" and a refresh token when it includes
// "offline_access", recording each onto result. Unlike the
// authorization code flow's, the ID token carries no nonce: CIBA has
// none.
func (s *Server) issueBackchannelOptionalTokens(ctx context.Context, client storage.RegisteredClient, grant grantRecord, accessToken string, binding refreshBinding, result *TokenResult) *Error {
	if containsScope(grant.Scope, "openid") {
		idToken, idErr := s.issueIDTokenForGrant(ctx, client, grant, "", accessToken)
		if idErr != nil {
			return idErr
		}
		result.IDToken = fapi.NewSecret(idToken)
		result.HasIDToken = true
	}
	if containsScope(grant.Scope, "offline_access") {
		refreshToken, err := s.issueRefreshToken(ctx, client.ID(), grant, binding)
		if err != nil {
			return newError(ErrorServerError, 500, "failed to issue refresh token", err)
		}
		result.RefreshToken = fapi.NewSecret(refreshToken)
		result.HasRefreshToken = true
	}
	return nil
}

// backchannelGrantID names the grant a CIBA request (authReqIDHash) was
// approved with, as an authorization code's grant is named after the
// code, so revoking a refresh token from its exchange (RevokeToken)
// ends every access token from the grant. "" when grants can't be
// revoked: no revocation store resource servers can read.
func (s *Server) backchannelGrantID(authReqIDHash [32]byte) string {
	if _, ok := s.grantRevocationReader(); !ok {
		return ""
	}
	return grantrevocation.BackchannelGrantID(authReqIDHash)
}

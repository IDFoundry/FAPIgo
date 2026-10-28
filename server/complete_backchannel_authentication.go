package server

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"strings"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/storage"
)

// invalidBackchannelHandleMessage is the one description given for a
// handle that can't be completed, whatever the reason.
const invalidBackchannelHandleMessage = "backchannel authentication handle is invalid, expired, or already decided"

// backchannelHandleHash is the SHA-256 digest of handle's raw wire
// value — matching storage.NewBackchannelAuthentication.HandleHash's
// digest-only discipline.
func backchannelHandleHash(handle BackchannelAuthenticationHandle) [32]byte {
	return sha256.Sum256([]byte(handle.String()))
}

// CompleteBackchannelAuthenticationRequest is the input to
// Server.CompleteBackchannelAuthentication.
type CompleteBackchannelAuthenticationRequest struct {
	Handle BackchannelAuthenticationHandle

	// Result is reused unmodified from the browser-based flow —
	// Authorize/Deny/AuthenticationFailed already express exactly the
	// three outcomes a CIBA decision can have.
	Result InteractionResult
}

// CompleteBackchannelAuthentication concludes a pending CIBA request
// previously started by BeginBackchannelAuthentication, once the
// embedder's own out-of-band authentication component has a decision:
// it records Result against Handle (single-use — a second call with the
// same handle fails), for a subsequent ExchangeBackchannelAuthentication
// poll to observe. A decision of any kind made once the request's
// lifetime has passed is refused with ErrorExpiredToken and not
// recorded, so a ping client is never notified about a request it can
// no longer redeem. Unlike CompleteAuthorization, there is no redirect to
// assemble here, so a nil return means success — there is no
// AuthorizationResult-style sum type to build, since CIBA has nothing
// to redirect to. A non-nil return is always a *Error (satisfying this
// package's usual errors.As(err, &serverErr) pattern), never a bare
// error from a dependency.
func (s *Server) CompleteBackchannelAuthentication(ctx context.Context, req CompleteBackchannelAuthenticationRequest) error {
	if s.deps.Backchannel == nil {
		return newError(ErrorServerError, 500, "backchannel authentication is not configured", nil)
	}
	handleHash := backchannelHandleHash(req.Handle)
	decision := storage.DecideBackchannelAuthentication{
		HandleHash: handleHash,
	}

	// Looked up for every outcome: an approval's granted scope and
	// details are validated against the original request (mirroring
	// completeAuthorize's identical check for the PAR flow), and no
	// decision of any kind is recorded once the request has expired.
	pending, lookupErr := s.deps.Backchannel.LookupBackchannelAuthentication(ctx, handleHash)
	if lookupErr != nil {
		wrapped := newError(ErrorInvalidRequest, 400, invalidBackchannelHandleMessage, lookupErr)
		s.audit(ctx, AuditEventCompleteBackchannelAuthentication, "", AuditOutcomeFailure, string(wrapped.Code()))
		return wrapped
	}
	request, decodeErr := s.decodeOwnRequestRecord(pending.Request)
	if decodeErr != nil {
		wrapped := recordFailure(decodeErr, newError(ErrorInvalidRequest, 400, invalidBackchannelHandleMessage, nil), "backchannel authentication request")
		s.audit(ctx, AuditEventCompleteBackchannelAuthentication, pending.ClientID, AuditOutcomeFailure, string(wrapped.Code()))
		return wrapped
	}
	if request.ExpiresAt != nil && !s.deps.Clock.Now().Before(*request.ExpiresAt) {
		wrapped := newError(ErrorExpiredToken, 400, "backchannel authentication request has expired", nil)
		s.audit(ctx, AuditEventCompleteBackchannelAuthentication, pending.ClientID, AuditOutcomeFailure, string(wrapped.Code()))
		return wrapped
	}

	switch result := req.Result.(type) {
	case authorizeResult:
		if failErr := s.approveBackchannelAuthentication(ctx, pending.ClientID, request, result, &decision); failErr != nil {
			return failErr
		}
	case denyResult:
		decision.Status = storage.BackchannelAuthenticationDenied
		decision.Reason = result.reason
	case denyLocallyResult:
		// Nothing redirects here, so it is Deny.
		decision.Status = storage.BackchannelAuthenticationDenied
		decision.Reason = result.reason
	case authenticationFailedResult:
		decision.Status = storage.BackchannelAuthenticationAuthenticationFailed
		decision.Reason = result.reason
	default:
		err := newError(ErrorServerError, 500, "unrecognized interaction result", nil)
		s.audit(ctx, AuditEventCompleteBackchannelAuthentication, "", AuditOutcomeFailure, string(err.Code()))
		return err
	}

	decided, err := s.deps.Backchannel.DecideBackchannelAuthentication(ctx, decision)
	if err != nil {
		wrapped := newError(ErrorInvalidRequest, 400, invalidBackchannelHandleMessage, err)
		s.audit(ctx, AuditEventCompleteBackchannelAuthentication, "", AuditOutcomeFailure, string(wrapped.Code()))
		return wrapped
	}

	// Ping notification dispatch is unconditional on Status — a client
	// registered for ping delivery needs to know "go poll now"
	// regardless of whether the decision was Approved, Denied or
	// AuthenticationFailed, and best-effort: a ping client may also poll
	// the token endpoint (CIBA §10.1), so a missed or failed notification
	// doesn't leave it stuck, and its error is never allowed to fail this
	// call
	// (mirrors the existing _ = s.deps.Revocation.Revoke(...) precedent
	// in server/token.go).
	s.notifyBackchannelPing(ctx, decided)

	s.audit(ctx, AuditEventCompleteBackchannelAuthentication, decided.ClientID, AuditOutcomeSuccess, "")
	return nil
}

// approveBackchannelAuthentication records an Authorize for the pending
// request in decision: approved, with its grant, or a failed
// authentication when it doesn't meet the request's essential acr or
// required subject. A result the request doesn't allow is an *Error,
// already audited.
func (s *Server) approveBackchannelAuthentication(ctx context.Context, clientID fapi.ClientID, request requestRecord, result authorizeResult, decision *storage.DecideBackchannelAuthentication) *Error {
	if result.subject.id.value == "" {
		err := newError(ErrorServerError, 500, "authorize result carries no authenticated subject", nil)
		s.audit(ctx, AuditEventCompleteBackchannelAuthentication, "", AuditOutcomeFailure, string(err.Code()))
		return err
	}
	// As for CompleteAuthorization: the authentication time must be
	// one that happened, neither missing nor in the future.
	if problem := result.auth.authTimeProblem(s.deps.Clock.Now(), s.cfg.Limits.MaxClockSkew); problem != "" {
		err := newError(ErrorServerError, 500, problem, nil)
		s.audit(ctx, AuditEventCompleteBackchannelAuthentication, "", AuditOutcomeFailure, string(err.Code()))
		return err
	}
	// The sub this client gets for the user, derived once here and kept
	// with the grant (see grantRecord.ClientSubject).
	clientSub, sector, subErr := s.subjectAtClient(ctx, clientID, result.subject.id.value)
	if subErr != nil {
		s.audit(ctx, AuditEventCompleteBackchannelAuthentication, clientID, AuditOutcomeFailure, string(subErr.Code()))
		return subErr
	}

	// OIDC Core §5.5.1.1: an essential "acr" request with values that
	// the authentication doesn't meet is a failed authentication, so
	// record it as one and issue nothing.
	if !meetsEssentialACR(request.EssentialACRValues, result.auth.acr) {
		decision.Status = storage.BackchannelAuthenticationAuthenticationFailed
		decision.Reason = "the user's authentication doesn't meet the requested essential acr"
		return nil
	}

	// OIDC Core §5.5.1: the user an id_token_hint or "sub" value
	// named must be the one authenticated; anyone else is a failed
	// authentication.
	if !meetsRequiredSubject(request.RequiredSubject, clientSub) {
		decision.Status = storage.BackchannelAuthenticationAuthenticationFailed
		decision.Reason = "the authenticated user isn't the one the request named"
		return nil
	}

	requestedScope, _ := jsonString(request.Parameters, "scope")
	if scopeErr := validateGrantedScopeSubset(result.grant.Scope, requestedScope); scopeErr != nil {
		wrapped := newError(ErrorInvalidRequest, 400, "granted scope exceeds requested scope", scopeErr)
		s.audit(ctx, AuditEventCompleteBackchannelAuthentication, clientID, AuditOutcomeFailure, string(wrapped.Code()))
		return wrapped
	}
	// A CIBA request carries "openid" (CIBA Core §7.1), and its token
	// response must carry an ID token (§10.1.1), so an approval can't
	// drop it. (A request stored before "openid" was required, without
	// it, isn't held to this.)
	if containsScope(strings.Fields(requestedScope), "openid") && !containsScope(result.grant.Scope, "openid") {
		wrapped := newError(ErrorInvalidRequest, 400, `granted scope must keep "openid", which a CIBA token response's ID token requires`, nil)
		s.audit(ctx, AuditEventCompleteBackchannelAuthentication, clientID, AuditOutcomeFailure, string(wrapped.Code()))
		return wrapped
	}

	resources, resourcesErr := grantedResources(request.Resources, result.grant.Resources)
	if resourcesErr != nil {
		s.audit(ctx, AuditEventCompleteBackchannelAuthentication, clientID, AuditOutcomeFailure, string(resourcesErr.Code()))
		return resourcesErr
	}

	if claimsErr := validateGrantedIDTokenClaims(result.grant.IDTokenClaims, s.cfg.Limits.MaxIDTokenClaimsBytes); claimsErr != nil {
		wrapped := newError(ErrorInvalidRequest, 400, "granted ID token claims are not valid", claimsErr)
		s.audit(ctx, AuditEventCompleteBackchannelAuthentication, clientID, AuditOutcomeFailure, string(wrapped.Code()))
		return wrapped
	}
	if idErr := s.validateGrantID(result.grant.GrantID); idErr != nil {
		wrapped := newError(ErrorInvalidRequest, 400, "the grant ID is not valid", idErr)
		s.audit(ctx, AuditEventCompleteBackchannelAuthentication, clientID, AuditOutcomeFailure, string(wrapped.Code()))
		return wrapped
	}

	var grantedAuthorizationDetails json.RawMessage
	if len(result.grant.AuthorizationDetails) > 0 {
		granted, validateErr := s.validateGrantedAuthorizationDetails(request.Parameters[authorizationDetailsParameter], result.grant.AuthorizationDetails)
		if validateErr != nil {
			wrapped := newError(ErrorInvalidRequest, 400, "granted authorization_details exceeds what was requested", validateErr)
			s.audit(ctx, AuditEventCompleteBackchannelAuthentication, clientID, AuditOutcomeFailure, string(wrapped.Code()))
			return wrapped
		}
		grantedAuthorizationDetails = granted
	}
	idTokenClaims, userinfoClaims, claimsErr := approvedClaimNames(request.Parameters, result.grant.ApprovedIdentityClaims)
	if claimsErr != nil {
		wrapped := newError(ErrorInvalidRequest, 400, "approved identity claims exceed what was requested", claimsErr)
		s.audit(ctx, AuditEventCompleteBackchannelAuthentication, clientID, AuditOutcomeFailure, string(wrapped.Code()))
		return wrapped
	}
	decidedAt := s.deps.Clock.Now()
	grant, encodeErr := s.encodeGrantRecord(grantRecord{
		Kind:                    grantKindBackchannel,
		IssuedAt:                &decidedAt,
		DPoPJKT:                 request.DPoPJKT,
		Subject:                 result.subject.ID().String(),
		ClientSubject:           distinctClientSubject(clientSub, result.subject.ID().String()),
		PairwiseSector:          sector,
		PairwisePrefix:          pairwisePrefixOf(s.cfg, sector),
		Scope:                   result.grant.Scope,
		AuthTime:                result.auth.authTime,
		ACR:                     result.auth.acr,
		AMR:                     result.auth.amr,
		AuthorizationDetails:    grantedAuthorizationDetails,
		Resources:               resources,
		TokenClaims:             request.TokenClaims,
		RequestedIDTokenClaims:  idTokenClaims,
		RequestedUserinfoClaims: userinfoClaims,
		IDTokenClaims:           result.grant.IDTokenClaims,
		GrantID:                 result.grant.GrantID,
		GrantType:               CIBAGrantType,
	})
	if encodeErr != nil {
		wrapped := newError(ErrorServerError, 500, "failed to encode backchannel authentication grant", encodeErr)
		s.audit(ctx, AuditEventCompleteBackchannelAuthentication, clientID, AuditOutcomeFailure, string(wrapped.Code()))
		return wrapped
	}
	decision.Status = storage.BackchannelAuthenticationApproved
	decision.Grant = grant
	return nil
}

// notifyBackchannelPing tells a ping client its request was decided,
// whatever the outcome, best-effort: a ping client may also poll.
func (s *Server) notifyBackchannelPing(ctx context.Context, decided storage.DecidedBackchannelAuthentication) {
	if decided.DeliveryMode != "ping" {
		return
	}
	if regClient, resolveErr := s.deps.Clients.ResolveClient(ctx, decided.ClientID); resolveErr == nil {
		if endpoint := regClient.BackchannelClientNotificationEndpoint(); !endpoint.IsZero() {
			_ = s.deps.BackchannelNotifier.Notify(ctx, BackchannelNotification{
				Endpoint:                endpoint,
				ClientNotificationToken: decided.ClientNotificationToken,
				AuthReqID:               decided.AuthReqID,
			})
		}
	}
}

package server

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"sync"

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
//
// A client registered for ping delivery is then notified, through
// Dependencies.BackchannelNotifier, and the call returns once the
// notification has been sent or has failed: a client whose notification
// endpoint doesn't answer holds it for as long as the notifier allows,
// backchannelhttp's Config.Timeout. Everything else is done first: the
// decision is recorded, the request leaves its user's inbox and the
// decision is audited, so a notification cut short, by ctx ending or
// otherwise, loses only the notification, and the client can poll
// instead (CIBA Core §10.1).
func (s *Server) CompleteBackchannelAuthentication(ctx context.Context, req CompleteBackchannelAuthenticationRequest) error {
	decided, err := s.recordBackchannelDecision(ctx, req)
	if err != nil {
		return err
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
	return nil
}

// recordBackchannelDecision is CompleteBackchannelAuthentication short
// of the ping notification: it records req's decision, takes the request
// out of its user's inbox and audits the decision, then returns what the
// store returned for it, which notifyBackchannelPing needs. A decision
// it refuses is an *Error, already audited.
func (s *Server) recordBackchannelDecision(ctx context.Context, req CompleteBackchannelAuthenticationRequest) (storage.DecidedBackchannelAuthentication, *Error) {
	if s.deps.Backchannel == nil {
		return storage.DecidedBackchannelAuthentication{}, newError(ErrorServerError, 500, "backchannel authentication is not configured", nil)
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
		wrapped := storeFailure(ctx, lookupErr, "failed to look up the backchannel authentication request", newError(ErrorInvalidRequest, 400, invalidBackchannelHandleMessage, lookupErr))
		s.audit(ctx, AuditEventCompleteBackchannelAuthentication, "", AuditOutcomeFailure, string(wrapped.Code()))
		return storage.DecidedBackchannelAuthentication{}, wrapped
	}
	request, decodeErr := s.decodeOwnRequestRecord(pending.Request)
	if decodeErr != nil {
		wrapped := recordFailure(decodeErr, newError(ErrorInvalidRequest, 400, invalidBackchannelHandleMessage, nil), "backchannel authentication request")
		s.audit(ctx, AuditEventCompleteBackchannelAuthentication, pending.ClientID, AuditOutcomeFailure, string(wrapped.Code()))
		return storage.DecidedBackchannelAuthentication{}, wrapped
	}
	if request.ExpiresAt != nil && !s.deps.Clock.Now().Before(*request.ExpiresAt) {
		wrapped := newError(ErrorExpiredToken, 400, "backchannel authentication request has expired", nil)
		s.audit(ctx, AuditEventCompleteBackchannelAuthentication, pending.ClientID, AuditOutcomeFailure, string(wrapped.Code()))
		return storage.DecidedBackchannelAuthentication{}, wrapped
	}

	switch result := req.Result.(type) {
	case authorizeResult:
		if failErr := s.approveBackchannelAuthentication(ctx, pending.ClientID, request, result, &decision); failErr != nil {
			return storage.DecidedBackchannelAuthentication{}, failErr
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
		return storage.DecidedBackchannelAuthentication{}, err
	}

	decided, err := s.deps.Backchannel.DecideBackchannelAuthentication(ctx, decision)
	if err != nil {
		wrapped := storeFailure(ctx, err, "failed to record the backchannel authentication decision", newError(ErrorInvalidRequest, 400, invalidBackchannelHandleMessage, err))
		s.audit(ctx, AuditEventCompleteBackchannelAuthentication, "", AuditOutcomeFailure, string(wrapped.Code()))
		return storage.DecidedBackchannelAuthentication{}, wrapped
	}

	// Both before the ping, which can take as long as the notifier
	// allows: the decided request leaves its user's inbox at once, and
	// its audit event can't be lost to a ctx that a client's unanswering
	// notification endpoint has run out.
	s.unfileBackchannelRequest(ctx, handleHash)
	s.audit(ctx, AuditEventCompleteBackchannelAuthentication, decided.ClientID, AuditOutcomeSuccess, "")
	return decided, nil
}

// backchannelAuthenticationFailure is why result's authentication fails
// request, or "" when it doesn't. Each of these is a failed
// authentication: an essential "acr" request with values the
// authentication doesn't meet (OIDC Core §5.5.1.1); a user other than
// the one an id_token_hint or "sub" value named (OIDC Core §5.5.1),
// which clientSub, the authenticated user's sub at the request's
// client, is checked against; and a user other than the one
// Dependencies.BackchannelSubjects bound the request to through its
// hint.
func backchannelAuthenticationFailure(request requestRecord, result authorizeResult, clientSub string) string {
	switch {
	case !meetsEssentialACR(request.EssentialACRValues, result.auth.acr):
		return "the user's authentication doesn't meet the requested essential acr"
	case !meetsRequiredSubject(request.RequiredSubject, clientSub):
		return "the authenticated user isn't the one the request named"
	case request.ResolvedSubject != "" && result.subject.id.value != request.ResolvedSubject:
		return "the authenticated user isn't the one the request's hint named"
	}
	return ""
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

	// A failed authentication is recorded as one, and nothing is issued.
	if reason := backchannelAuthenticationFailure(request, result, clientSub); reason != "" {
		decision.Status = storage.BackchannelAuthenticationAuthenticationFailed
		decision.Reason = reason
		return nil
	}

	if scopeErr := grantedBackchannelScopeError(request, result.grant.Scope); scopeErr != nil {
		s.audit(ctx, AuditEventCompleteBackchannelAuthentication, clientID, AuditOutcomeFailure, string(scopeErr.Code()))
		return scopeErr
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
		Kind:                         grantKindBackchannel,
		IssuedAt:                     &decidedAt,
		DPoPJKT:                      request.DPoPJKT,
		Subject:                      result.subject.ID().String(),
		ClientSubject:                distinctClientSubject(clientSub, result.subject.ID().String()),
		PairwiseSector:               sector,
		PairwisePrefix:               pairwisePrefixOf(s.cfg, sector),
		Scope:                        result.grant.Scope,
		AuthTime:                     result.auth.authTime,
		ACR:                          result.auth.acr,
		AMR:                          result.auth.amr,
		AuthorizationDetails:         grantedAuthorizationDetails,
		Resources:                    resources,
		TokenClaims:                  request.TokenClaims,
		RequestedIDTokenClaims:       idTokenClaims,
		RequestedUserinfoClaims:      userinfoClaims,
		RequestedIDTokenClaimValues:  requestedClaimValues(request.Parameters, "id_token", idTokenClaims),
		RequestedUserinfoClaimValues: requestedClaimValues(request.Parameters, "userinfo", userinfoClaims),
		IDTokenClaims:                result.grant.IDTokenClaims,
		GrantID:                      result.grant.GrantID,
		GrantType:                    CIBAGrantType,
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

// grantedBackchannelScopeError checks an approval's granted scope
// against the request's: a non-empty subset of it that, when the request
// asked for "openid", keeps it. A CIBA request carries "openid" (CIBA
// Core §7.1), and its token response must carry an ID token (§10.1.1),
// so an approval can't drop it. (A request stored before "openid" was
// required, without it, isn't held to this.)
func grantedBackchannelScopeError(request requestRecord, granted []string) *Error {
	requestedScope, _ := jsonString(request.Parameters, "scope")
	if scopeErr := validateGrantedScopeSubset(granted, requestedScope); scopeErr != nil {
		return newError(ErrorInvalidRequest, 400, "granted scope is empty or exceeds requested scope", scopeErr)
	}
	if containsScope(strings.Fields(requestedScope), "openid") && !containsScope(granted, "openid") {
		return newError(ErrorInvalidRequest, 400, `granted scope must keep "openid", which a CIBA token response's ID token requires`, nil)
	}
	return nil
}

// maxConcurrentBackchannelPings bounds how many ping notifications
// notifyBackchannelPings sends at once: as many as one client may have
// requests pending for one end user under the default
// Limits.MaxPendingBackchannelAuthenticationRequestsPerClient, so that
// one client's requests don't wait on each other, while a bulk denial
// still opens only so many connections at a time to endpoints its
// clients registered.
const maxConcurrentBackchannelPings = 8

// notifyBackchannelPings notifies the ping clients among decided, as
// notifyBackchannelPing notifies one, sending up to
// maxConcurrentBackchannelPings notifications at once, and returns once
// each has been sent or has failed: ctx and the client repository's own
// limits bound the lookup of its client, and ctx and the notifier's own
// timeout the notification itself, so nothing is left sending after it
// returns. A notifier that panics doesn't take the process down from a
// goroutine of this package's: once the other notifications are done,
// its panic is raised again here, in the caller's goroutine, where a
// single decision's notification would have raised it.
func (s *Server) notifyBackchannelPings(ctx context.Context, decided []storage.DecidedBackchannelAuthentication) {
	var (
		wg       sync.WaitGroup
		first    sync.Once
		panicked any
	)
	slots := make(chan struct{}, maxConcurrentBackchannelPings)
	for _, d := range decided {
		slots <- struct{}{}
		wg.Go(func() {
			defer func() {
				<-slots
				if r := recover(); r != nil {
					first.Do(func() { panicked = r })
				}
			}()
			s.notifyBackchannelPing(ctx, d)
		})
	}
	wg.Wait()
	if panicked != nil {
		panic(panicked)
	}
}

// notifyBackchannelPing tells a ping client its request was decided,
// whatever the outcome, best-effort: a ping client may also poll.
func (s *Server) notifyBackchannelPing(ctx context.Context, decided storage.DecidedBackchannelAuthentication) {
	if decided.DeliveryMode != "ping" || !s.backchannelPingSupported() {
		// A request begun for ping before the server declined ping
		// delivery is left to poll, as the client may.
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

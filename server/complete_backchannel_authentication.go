package server

import (
	"context"
	"crypto/sha256"

	"github.com/idfoundry/fapigo/storage"
)

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
// poll to observe. Unlike CompleteAuthorization, there is no redirect to
// assemble here, so a nil return means success — there is no
// AuthorizationResult-style sum type to build, since CIBA has nothing
// to redirect to. A non-nil return is always a *Error (satisfying this
// package's usual errors.As(err, &serverErr) pattern), never a bare
// error from a dependency.
func (s *Server) CompleteBackchannelAuthentication(ctx context.Context, req CompleteBackchannelAuthenticationRequest) error {
	decision := storage.DecideBackchannelAuthentication{
		HandleHash: backchannelHandleHash(req.Handle),
	}

	switch result := req.Result.(type) {
	case authorizeResult:
		if result.subject.id.value == "" {
			err := newError(ErrorServerError, 500, "authorize result carries no authenticated subject", nil)
			s.audit(ctx, AuditEventCompleteBackchannelAuthentication, "", AuditOutcomeFailure, string(err.Code()))
			return err
		}
		decision.Status = storage.BackchannelAuthenticationApproved
		decision.Subject = result.subject.ID().String()
		decision.Scope = result.grant.Scope
		decision.AuthTime = result.auth.authTime
		decision.ACR = result.auth.acr
		decision.AMR = result.auth.amr
	case denyResult:
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
		wrapped := newError(ErrorInvalidRequest, 400, "backchannel authentication handle is invalid, expired, or already decided", err)
		s.audit(ctx, AuditEventCompleteBackchannelAuthentication, "", AuditOutcomeFailure, string(wrapped.Code()))
		return wrapped
	}

	// Ping notification dispatch is unconditional on Status — a client
	// registered for ping delivery needs to know "go poll now"
	// regardless of whether the decision was Approved, Denied or
	// AuthenticationFailed, and best-effort: CIBA §10.3's backup-polling
	// guarantee means a missed or failed notification never leaves the
	// client stuck, so its error is never allowed to fail this call
	// (mirrors the existing _ = s.deps.Revocation.Revoke(...) precedent
	// in server/token.go).
	if decided.DeliveryMode == "ping" {
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

	s.audit(ctx, AuditEventCompleteBackchannelAuthentication, decided.ClientID, AuditOutcomeSuccess, "")
	return nil
}

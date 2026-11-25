package server

import (
	"context"
	"time"

	fapi "github.com/idfoundry/fapigo"
)

// AuditEventType is a closed set of security-significant events the
// server can record.
type AuditEventType uint8

const (
	_ AuditEventType = iota

	// AuditEventPushAuthorizationRequest records the outcome of a
	// PushAuthorizationRequest call.
	AuditEventPushAuthorizationRequest

	// AuditEventBeginAuthorization records the outcome of a
	// BeginAuthorization call.
	AuditEventBeginAuthorization

	// AuditEventCompleteAuthorization records the outcome of a
	// CompleteAuthorization call.
	AuditEventCompleteAuthorization

	// AuditEventExchangeAuthorizationCode records the outcome of an
	// ExchangeAuthorizationCode call.
	AuditEventExchangeAuthorizationCode

	// AuditEventRefreshAccessToken records the outcome of a
	// RefreshAccessToken call.
	AuditEventRefreshAccessToken

	// AuditEventBeginBackchannelAuthentication records the outcome of a
	// BeginBackchannelAuthentication call.
	AuditEventBeginBackchannelAuthentication

	// AuditEventCompleteBackchannelAuthentication records the outcome of
	// a CompleteBackchannelAuthentication call.
	AuditEventCompleteBackchannelAuthentication

	// AuditEventExchangeBackchannelAuthentication records the outcome of
	// an ExchangeBackchannelAuthentication call.
	AuditEventExchangeBackchannelAuthentication

	// AuditEventRequestClientCredentialsToken records the outcome of a
	// RequestClientCredentialsToken call.
	AuditEventRequestClientCredentialsToken

	// AuditEventAuthenticateAttestedClient records the outcome of an
	// AuthenticateAttestedClient call.
	AuditEventAuthenticateAttestedClient

	// AuditEventVerifyTokenRequestBinding records the outcome of a
	// VerifyTokenRequestBinding call.
	AuditEventVerifyTokenRequestBinding

	// AuditEventIssueRefreshToken records the outcome of an
	// IssueRefreshToken call.
	AuditEventIssueRefreshToken

	// AuditEventRevokeToken records the outcome of a RevokeToken call.
	AuditEventRevokeToken

	// AuditEventIssueAccessToken records the outcome of an
	// IssueAccessToken call.
	AuditEventIssueAccessToken

	// AuditEventVerifyTokenRequestDPoP records the outcome of a
	// VerifyTokenRequestDPoP call. Its ClientID is always "": the
	// request has no authenticated client.
	AuditEventVerifyTokenRequestDPoP

	// AuditEventRevokeReusedAuthorizationCode records the revocation of
	// what an authorization code issued, when the client it was issued
	// to presents it again, with the code_verifier, redirect_uri and
	// DPoP key it was issued for, after redeeming it (RFC 6749 §4.1.2).
	// The ExchangeAuthorizationCode call presenting it still records its
	// own failed AuditEventExchangeAuthorizationCode. Outcome is
	// AuditOutcomeFailure when a revocation couldn't be written, so
	// something issued from the code may still be accepted.
	AuditEventRevokeReusedAuthorizationCode
)

// AuditOutcome is a closed set of outcomes for an AuditEvent.
type AuditOutcome uint8

const (
	_ AuditOutcome = iota
	AuditOutcomeSuccess
	AuditOutcomeFailure
)

// AuditEvent is a structured, security-significant event. Description is
// a short, safe summary (e.g. an ErrorCode) — never a raw internal error
// or anything that could carry a token, key or assertion value.
type AuditEvent struct {
	Type        AuditEventType
	Time        time.Time
	ClientID    fapi.ClientID // "" if the client could not be identified
	Outcome     AuditOutcome
	Description string
}

// AuditSink records AuditEvents. Under AssuranceProduction, New requires
// one to be configured.
//
// By default auditing is best-effort: an error from Record is discarded
// and the operation it describes carries on as if the event had been
// recorded. A sink that also implements FailClosedAuditSink, with
// AuditFailsClosed returning true, makes the events listed there fail
// the operation instead.
type AuditSink interface {
	Record(ctx context.Context, event AuditEvent) error
}

// FailClosedAuditSink is an AuditSink that requires certain events to be
// recorded before the operation they describe reports success. New asks
// AuditFailsClosed once; when it returns true, an error from Record for
// one of these events makes the operation answer server_error (HTTP 500)
// instead, its cause being Record's error:
//
//   - a successful AuditEventExchangeAuthorizationCode,
//     AuditEventRefreshAccessToken,
//     AuditEventExchangeBackchannelAuthentication,
//     AuditEventRequestClientCredentialsToken, AuditEventIssueAccessToken
//     or AuditEventIssueRefreshToken: a token was issued;
//   - a successful AuditEventRevokeToken: a token revocation request
//     was answered;
//   - any AuditEventRevokeReusedAuthorizationCode: a reused
//     authorization code was presented, and what it issued revoked (or
//     not all of it). That request is refused either way; failing closed
//     turns its invalid_grant into server_error, so the deployment's own
//     error handling sees an unrecorded code reuse.
//
// Every other event, and every failure outcome of the events above, stays
// best-effort: the request is already refused, or (PAR, authorization,
// CIBA approval, client and binding checks) nothing usable has been
// issued yet — the token exchange that would issue it fails closed.
//
// The event is recorded after the state change it describes, just before
// the result is returned, so failing closed guarantees that no token
// reaches the client, and no revocation is acknowledged, without its
// event having been accepted by Record. It can't undo the state change:
//
//   - An authorization code or CIBA approval is already spent, so the
//     client must start over (presenting the code again is a reuse, and
//     revokes what it issued). A refresh token presented to
//     RefreshAccessToken stays usable, since it isn't rotated; for
//     IssueAccessToken and IssueRefreshToken, whatever the embedder
//     itself spent before calling stays spent.
//   - A token minted for the failed response — an access token, an ID
//     token, a new refresh token — may already be recorded in the
//     deployment's stores (and a JWT access token is valid until it
//     expires to whoever holds it), but it is never returned, and the
//     stores keep only digests, so nobody holds it.
//   - A revocation has already been written; the client retries, and
//     revoking again succeeds as before.
//
// A failed success event is followed by a best-effort failure event for
// the same operation (outcome AuditOutcomeFailure, description
// "server_error"), as every other failure is. Record returning an error
// for an event it did in fact persist (a timeout after a write, say)
// fails the request all the same: the log then holds a success the
// client never saw.
//
// A declaration describes the declaring type's own behaviour. A sink
// embedding one that declares it inherits the declaration through Go's
// method promotion; a wrapper whose own Record can't promise the same
// must override AuditFailsClosed.
type FailClosedAuditSink interface {
	AuditSink
	AuditFailsClosed() bool
}

// auditFailsClosed reports whether sink declares, through
// FailClosedAuditSink, that the events it lists must be recorded.
func auditFailsClosed(sink AuditSink) bool {
	failClosed, ok := sink.(FailClosedAuditSink)
	return ok && failClosed.AuditFailsClosed()
}

// audit records an event best-effort: see AuditSink.
func (s *Server) audit(ctx context.Context, eventType AuditEventType, clientID fapi.ClientID, outcome AuditOutcome, description string) {
	_ = s.recordAudit(ctx, eventType, clientID, outcome, description)
}

// auditRequired records an event FailClosedAuditSink lists, and returns
// the server_error to answer with instead of the operation's result when
// the sink fails closed and couldn't record it; nil otherwise.
func (s *Server) auditRequired(ctx context.Context, eventType AuditEventType, clientID fapi.ClientID, outcome AuditOutcome, description string) *Error {
	err := s.recordAudit(ctx, eventType, clientID, outcome, description)
	if err == nil || !s.auditFailsClosed {
		return nil
	}
	return newError(ErrorServerError, 500, "failed to record an audit event", err)
}

func (s *Server) recordAudit(ctx context.Context, eventType AuditEventType, clientID fapi.ClientID, outcome AuditOutcome, description string) error {
	if s.deps.Audit == nil {
		return nil
	}
	return s.deps.Audit.Record(ctx, AuditEvent{
		Type:        eventType,
		Time:        s.deps.Clock.Now(),
		ClientID:    clientID,
		Outcome:     outcome,
		Description: description,
	})
}

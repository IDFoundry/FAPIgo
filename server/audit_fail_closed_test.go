package server_test

import (
	"context"
	"errors"
	"testing"

	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

var errAuditDown = errors.New("audit log unavailable")

// erroringAuditSink is a fakeAuditSink whose Record fails, recording
// nothing, for the events fails picks. It declares nothing, as every
// sink written before FailClosedAuditSink.
type erroringAuditSink struct {
	*fakeAuditSink
	fails func(server.AuditEvent) bool
}

func (s *erroringAuditSink) Record(ctx context.Context, event server.AuditEvent) error {
	if s.fails(event) {
		return errAuditDown
	}
	return s.fakeAuditSink.Record(ctx, event)
}

// failClosedAuditSink is an erroringAuditSink declaring failsClosed
// through server.FailClosedAuditSink.
type failClosedAuditSink struct {
	*erroringAuditSink
	failsClosed bool
}

func (s *failClosedAuditSink) AuditFailsClosed() bool { return s.failsClosed }

// auditSinkKind is how a test's erroring sink declares itself.
type auditSinkKind int

const (
	sinkUndeclared auditSinkKind = iota
	sinkDeclaresBestEffort
	sinkFailsClosed
)

// withErroringAudit is h with its server rebuilt over the same stores
// and an audit sink of kind failing the events fails picks. h.audit is
// the sink's record of the events it did record.
func withErroringAudit(t *testing.T, h harness, kind auditSinkKind, fails func(server.AuditEvent) bool) harness {
	t.Helper()
	if h.audit == nil {
		h.audit = &fakeAuditSink{}
	}
	erroring := &erroringAuditSink{fakeAuditSink: h.audit, fails: fails}
	var sink server.AuditSink = erroring
	if kind != sinkUndeclared {
		sink = &failClosedAuditSink{erroringAuditSink: erroring, failsClosed: kind == sinkFailsClosed}
	}
	return withDependencies(t, h, func(d *server.Dependencies) { d.Audit = sink })
}

// successOf picks eventType's successful events.
func successOf(eventType server.AuditEventType) func(server.AuditEvent) bool {
	return func(e server.AuditEvent) bool { return e.Type == eventType && e.Outcome == server.AuditOutcomeSuccess }
}

// failClosedFlow is an operation whose successful event a
// FailClosedAuditSink must record: run prepares a harness, has
// rebuild swap in the sink just before the operation, and reports the
// operation's error and whether it returned anything.
type failClosedFlow struct {
	event server.AuditEventType
	run   func(t *testing.T, rebuild func(harness) harness) (returned bool, err error)
}

func failClosedFlows() map[string]failClosedFlow {
	return map[string]failClosedFlow{
		"authorization code exchange": {server.AuditEventExchangeAuthorizationCode, runCodeExchange},
		"refresh":                     {server.AuditEventRefreshAccessToken, runRefresh},
		"client credentials":          {server.AuditEventRequestClientCredentialsToken, runClientCredentials},
		"CIBA exchange":               {server.AuditEventExchangeBackchannelAuthentication, runBackchannelExchange},
		"embedder access token":       {server.AuditEventIssueAccessToken, runIssueAccessToken},
		"embedder refresh token":      {server.AuditEventIssueRefreshToken, runIssueRefreshToken},
		"token revocation":            {server.AuditEventRevokeToken, runRevokeToken},
	}
}

func runCodeExchange(t *testing.T, rebuild func(harness) harness) (bool, error) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts", "offline_access"})
	result, err := exchangeCode(t, rebuild(h), code, generateKey(t))
	return result.AccessToken.Reveal() != "" || result.HasRefreshToken || result.HasIDToken, err
}

func runRefresh(t *testing.T, rebuild func(harness) harness) (bool, error) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	first, dpopKey := exchangeForTokensWithOfflineAccess(t, h)
	h = rebuild(h)
	result, err := h.server.RefreshAccessToken(context.Background(), server.RefreshTokenRequest{
		HTTP:       server.FormRequest{Parameters: refreshFormParams(h.clientAssertion(t), first.RefreshToken.Reveal(), "")},
		DPoPProofs: []string{createDPoPProof(t, dpopKey, h.now)},
	})
	return result.AccessToken.Reveal() != "" || result.HasRefreshToken, err
}

func runClientCredentials(t *testing.T, rebuild func(harness) harness) (bool, error) {
	h := rebuild(newHarnessWithClientCredentialsGrant(t, storage.SenderConstrainDPoP, true))
	result, err := h.server.RequestClientCredentialsToken(context.Background(), server.ClientCredentialsTokenRequest{
		HTTP:       server.FormRequest{Parameters: clientCredentialsFormParams(h.clientAssertion(t), "accounts")},
		DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
	})
	return result.AccessToken.Reveal() != "", err
}

func runBackchannelExchange(t *testing.T, rebuild func(harness) harness) (bool, error) {
	h, _ := newHarnessWithBackchannel(t)
	required := beginBackchannel(t, h, standardBackchannelParams(t))
	approveBackchannel(t, h, required.Handle)
	h = rebuild(h)
	return false, exchangeBackchannelWithKey(t, h, required.AuthReqID.String(), generateKey(t))
}

func runIssueAccessToken(t *testing.T, rebuild func(harness) harness) (bool, error) {
	attesterKey := generateKey(t)
	h := rebuild(newEmbedderRefreshHarness(t, attesterKey))
	instance := &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}
	result, err := h.server.IssueAccessToken(context.Background(), embedderAccessTokenRequest(t, instance, generateKey(t)))
	return result.AccessToken.Reveal() != "", err
}

func runIssueRefreshToken(t *testing.T, rebuild func(harness) harness) (bool, error) {
	attesterKey := generateKey(t)
	h := rebuild(newEmbedderRefreshHarness(t, attesterKey))
	instance := &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}
	attested, binding := embedderTokenRequest(t, instance)
	refreshToken, err := h.server.IssueRefreshToken(context.Background(), server.IssueRefreshTokenRequest{
		GrantType: preAuthorizedCodeGrant, Client: attested, Binding: binding,
		Subject: mustSubjectID(t, "holder-1"), Scope: []string{"accounts"},
	})
	return refreshToken.Reveal() != "", err
}

func runRevokeToken(t *testing.T, rebuild func(harness) harness) (bool, error) {
	_, owner, refreshToken := issueGrantOneRefreshToken(t)
	owner.h = rebuild(owner.h)
	result, err := owner.revokeResult(formParam("token", refreshToken))
	return result.Revoked, err
}

// TestFailClosedAuditFailsIssuance: a FailClosedAuditSink that can't
// record an issuing operation's success fails it with server_error,
// returning nothing, and records the failure in its place.
func TestFailClosedAuditFailsIssuance(t *testing.T) {
	for name, flow := range failClosedFlows() {
		t.Run(name, func(t *testing.T) {
			var audit *fakeAuditSink
			returned, err := flow.run(t, func(h harness) harness {
				h = withErroringAudit(t, h, sinkFailsClosed, successOf(flow.event))
				audit = h.audit
				return h
			})
			requireServerErrorCode(t, err, server.ErrorServerError)
			if !errors.Is(err, errAuditDown) {
				t.Errorf("error = %v, want the sink's error as its cause", err)
			}
			if returned {
				t.Error("the failed operation still returned what it issued")
			}
			requireFailureAuditedLast(t, audit.all(), flow.event)
		})
	}
}

// requireFailureAuditedLast fails unless events end with eventType's
// server_error failure.
func requireFailureAuditedLast(t *testing.T, events []server.AuditEvent, eventType server.AuditEventType) {
	t.Helper()
	if len(events) == 0 {
		t.Fatal("no audit events recorded")
	}
	last := events[len(events)-1]
	if last.Type != eventType || last.Outcome != server.AuditOutcomeFailure || last.Description != string(server.ErrorServerError) {
		t.Errorf("last audit event = %+v, want a server_error failure of type %v", last, eventType)
	}
}

// TestBestEffortAuditKeepsIssuing: a sink that doesn't declare
// FailClosedAuditSink, or declares it false, failing the same events
// leaves every operation succeeding, as before.
func TestBestEffortAuditKeepsIssuing(t *testing.T) {
	for kindName, kind := range map[string]auditSinkKind{"undeclared": sinkUndeclared, "declared off": sinkDeclaresBestEffort} {
		for name, flow := range failClosedFlows() {
			t.Run(kindName+"/"+name, func(t *testing.T) {
				_, err := flow.run(t, func(h harness) harness {
					return withErroringAudit(t, h, kind, successOf(flow.event))
				})
				if err != nil {
					t.Fatalf("operation failed: %v", err)
				}
			})
		}
	}
}

// TestFailClosedAuditLeavesOtherEventsBestEffort: a FailClosedAuditSink
// failing every event leaves PAR, authorization and its completion
// succeeding, and an exchange refused for its own reason refused as
// before rather than with server_error.
func TestFailClosedAuditLeavesOtherEventsBestEffort(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	h = withErroringAudit(t, h, sinkFailsClosed, func(server.AuditEvent) bool { return true })
	completeSuccessfulAuthorization(t, h, []string{"openid", "accounts"})
	_, err := exchangeCode(t, h, "not-a-code", generateKey(t))
	requireInvalidGrant(t, err)
}

// TestFailClosedAuditOnCodeReuse: a FailClosedAuditSink that can't
// record a revoking reuse turns the reuse's invalid_grant into
// server_error; a best-effort sink leaves it invalid_grant.
func TestFailClosedAuditOnCodeReuse(t *testing.T) {
	for name, tc := range map[string]struct {
		kind auditSinkKind
		want server.ErrorCode
	}{
		"fails closed": {sinkFailsClosed, server.ErrorServerError},
		"undeclared":   {sinkUndeclared, server.ErrorInvalidGrant},
		"declared off": {sinkDeclaresBestEffort, server.ErrorInvalidGrant},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, server.ProfileFAPISecurity, true)
			dpopKey := generateKey(t)
			code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts", "offline_access"})
			if _, err := exchangeCode(t, h, code, dpopKey); err != nil {
				t.Fatalf("ExchangeAuthorizationCode: %v", err)
			}
			h = withErroringAudit(t, h, tc.kind, func(e server.AuditEvent) bool {
				return e.Type == server.AuditEventRevokeReusedAuthorizationCode
			})
			_, err := exchangeCode(t, h, code, dpopKey)
			requireServerErrorCode(t, err, tc.want)
			if len(h.revocation.all()) == 0 {
				t.Error("the reuse revoked nothing")
			}
		})
	}
}

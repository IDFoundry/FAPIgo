package server_test

import (
	"context"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/server"
)

// TestBeginAuthorizationAuditsUnverifiedClientIDAsNone: until the
// query's client_id matches the client that pushed the request, it's
// only what the browser claims, so a failure is audited with no client.
// A value carrying a forged log line never reaches the audit sink.
func TestBeginAuthorizationAuditsUnverifiedClientIDAsNone(t *testing.T) {
	const forged = "nobody\r\n2026-10-09T00:00:00Z AUDIT begin_authorization client=admin outcome=success"
	ctx := context.Background()

	for name, tc := range map[string]struct {
		requestURI func(t *testing.T, h harness) string
		clientID   string
	}{
		"unrecognised request_uri": {func(*testing.T, harness) string { return "not-a-request-uri" }, forged},
		"unknown request_uri": {func(*testing.T, harness) string {
			return "urn:ietf:params:oauth:request_uri:unknown"
		}, forged},
		"client_id doesn't match the pushed request": {pushForAudit, forged},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, server.ProfileFAPISecurity, true)
			action, err := h.server.BeginAuthorization(ctx, server.BeginAuthorizationRequest{RequestURI: tc.requestURI(t, h), ClientID: fapi.ClientID(tc.clientID)})
			if err != nil {
				t.Fatalf("BeginAuthorization: %v", err)
			}
			if _, ok := action.(server.LocalErrorResponse); !ok {
				t.Fatalf("action = %T, want LocalErrorResponse", action)
			}
			if ev := lastBeginAuthorizationAudit(t, h); ev.Outcome != server.AuditOutcomeFailure || ev.ClientID != "" {
				t.Fatalf("audit event = %+v, want a failure with no client", ev)
			}
		})
	}

	t.Run("verified client is audited", func(t *testing.T) {
		h := newHarness(t, server.ProfileFAPISecurity, true)
		if _, err := h.server.BeginAuthorization(ctx, server.BeginAuthorizationRequest{RequestURI: pushForAudit(t, h), ClientID: testClientID}); err != nil {
			t.Fatalf("BeginAuthorization: %v", err)
		}
		if ev := lastBeginAuthorizationAudit(t, h); ev.Outcome != server.AuditOutcomeSuccess || ev.ClientID != testClientID {
			t.Fatalf("audit event = %+v, want a success for %s", ev, testClientID)
		}
	})
}

// pushForAudit pushes a plain-parameter request for h's client and
// returns its request_uri.
func pushForAudit(t *testing.T, h harness) string {
	t.Helper()
	pushed, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: plainFormParameters(t, h.clientAssertion(t), nil)},
	})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
	return pushed.RequestURI.String()
}

// lastBeginAuthorizationAudit returns h's most recent
// begin_authorization audit event.
func lastBeginAuthorizationAudit(t *testing.T, h harness) server.AuditEvent {
	t.Helper()
	events := h.audit.all()
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Type == server.AuditEventBeginAuthorization {
			return events[i]
		}
	}
	t.Fatal("no begin_authorization audit event")
	return server.AuditEvent{}
}

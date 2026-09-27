package client_test

import (
	"context"
	"strings"
	"testing"

	"github.com/idfoundry/fapigo/client"
)

// TestCallbackMustBeBoundToItsSession covers RFC 9700 §4.7's user-agent
// binding: a callback is completed only by the session that began it,
// and a rejected callback leaves that session intact.
func TestCallbackMustBeBoundToItsSession(t *testing.T) {
	for _, messageSigned := range []bool{false, true} {
		name := "plain"
		if messageSigned {
			name = "JARM"
		}
		t.Run(name, func(t *testing.T) {
			c, as, _ := newTestClient(t, messageSigned)
			ctx := context.Background()
			scope := []string{"openid", "accounts"}

			// The fake AS issues its ID token with the most recent PAR's
			// nonce, so the flow the test completes is begun last.
			other, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: scope})
			if err != nil {
				t.Fatalf("BeginAuthorization: %v", err)
			}
			mine, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: scope})
			if err != nil {
				t.Fatalf("BeginAuthorization: %v", err)
			}
			callback := as.callbackFor(t, mine.Handle().String(), "auth-code-123", "")

			for label, session := range map[string]client.SessionHandle{
				"no session":             {},
				"another flow's session": other.Handle(),
			} {
				_, err := c.HandleAuthorizationResponse(ctx, client.AuthorizationCallback{RawQuery: callback, Session: session})
				if code := clientErrorCode(t, err); code != client.ErrorInvalidRequest {
					t.Fatalf("%s: error code = %q, want %q", label, code, client.ErrorInvalidRequest)
				}
			}

			// Neither rejection consumed the session: its own browser
			// still completes it.
			result, err := c.CompleteAuthorization(ctx, client.AuthorizationCallback{RawQuery: callback, Session: mine.Handle()})
			if err != nil {
				t.Fatalf("CompleteAuthorization (own session): %v", err)
			}
			if _, ok := result.(client.CompletionSuccess); !ok {
				t.Fatalf("result = %T, want client.CompletionSuccess", result)
			}
		})
	}
}

func TestParseSessionHandle(t *testing.T) {
	c, _, _ := newTestClient(t, false)
	session, err := c.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{Scope: []string{"openid"}})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	parsed, err := client.ParseSessionHandle(session.Handle().String())
	if err != nil || parsed != session.Handle() {
		t.Fatalf("ParseSessionHandle(String()) = %v, %v; want the same handle", parsed, err)
	}
	valid := session.Handle().String()
	for name, s := range map[string]string{
		"empty":        "",
		"not base64":   "!!!",
		"too short":    valid[:len(valid)-4],
		"too long":     valid + "AAAA",
		"padded":       valid + "=",
		"standard b64": strings.ReplaceAll(strings.ReplaceAll(valid, "-", "+"), "_", "/") + "+",
	} {
		if _, err := client.ParseSessionHandle(s); err == nil {
			t.Errorf("ParseSessionHandle(%s) = nil error, want error", name)
		}
	}
}

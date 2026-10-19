package client_test

import (
	"context"
	"testing"

	"github.com/idfoundry/fapigo/client"
)

// TestOmittedScopeIsTheRequestedOne: RFC 6749 §5.1 has a token response
// omit "scope" only when it's "identical to the scope requested by the
// client", so the TokenSet records that scope rather than none.
func TestOmittedScopeIsTheRequestedOne(t *testing.T) {
	ctx := context.Background()

	c, as, _ := newTestClient(t, false)
	as.omitScope = true
	session, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid", "accounts"}})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	rawQuery := as.callbackFor(t, session.Handle().String(), "auth-code-123", "")
	result, err := c.CompleteAuthorization(ctx, client.AuthorizationCallback{RawQuery: rawQuery, Session: session.Handle()})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	success, ok := result.(client.CompletionSuccess)
	if !ok {
		t.Fatalf("result type = %T, want client.CompletionSuccess", result)
	}
	if success.Tokens.Scope != "openid accounts" {
		t.Errorf("authorization code: Scope = %q, want the requested %q", success.Tokens.Scope, "openid accounts")
	}

	cc, ccAS := newTestClientForClientCredentials(t, nil)
	ccAS.omitScope = true
	tokens, err := cc.RequestClientCredentialsToken(ctx, client.ClientCredentialsTokenRequest{Scope: []string{"accounts"}})
	if err != nil {
		t.Fatalf("RequestClientCredentialsToken: %v", err)
	}
	if tokens.Scope != "accounts" {
		t.Errorf("client credentials: Scope = %q, want the requested %q", tokens.Scope, "accounts")
	}
}

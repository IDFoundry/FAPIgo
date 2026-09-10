package fapitest_test

import (
	"context"
	"testing"

	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/fapitest"
	"github.com/idfoundry/fapigo/server"
)

// TestOAuthOnlyServerIssuesTokensWithoutOpenIDScope proves a
// Config.OAuthOnly server still drives an ordinary authorization_code
// flow end to end over real HTTP — OAuthOnly narrows what's on offer, it
// doesn't disable the AS.
func TestOAuthOnlyServerIssuesTokensWithoutOpenIDScope(t *testing.T) {
	h := fapitest.New(t, fapitest.Config{Profile: server.ProfileFAPISecurity, OAuthOnly: true})
	ctx := context.Background()

	tokens, err := h.RunAuthorizationCodeFlow(ctx, []string{"accounts"})
	if err != nil {
		t.Fatalf("RunAuthorizationCodeFlow: %v", err)
	}
	if tokens.AccessToken.Reveal() == "" {
		t.Fatalf("AccessToken is empty")
	}
	if tokens.HasIDToken {
		t.Fatalf("HasIDToken = true, want false — OAuthOnly never issues one")
	}
}

// TestOAuthOnlyServerRejectsOpenIDScope confirms the real wire path
// (client.Client.BeginAuthorization -> real PAR call) surfaces the AS's
// refusal, not just the unit-level check in server/par_test.go — the
// harness's own registered client keeps "openid" in its AllowedScopes
// (see fapitest.Config.OAuthOnly's own doc comment), so this proves the
// server-wide override, not an unregistered scope.
func TestOAuthOnlyServerRejectsOpenIDScope(t *testing.T) {
	h := fapitest.New(t, fapitest.Config{Profile: server.ProfileFAPISecurity, OAuthOnly: true})
	ctx := context.Background()

	_, err := h.Client.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid", "accounts"}})
	if err == nil {
		t.Fatalf("BeginAuthorization(openid scope) = nil error, want error")
	}
}

package fapitest_test

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/fapitest"
	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/server"
)

func TestAuthorizationCodeFlowBaseline(t *testing.T) {
	h := fapitest.New(t, fapitest.Config{Profile: server.ProfileFAPISecurity})
	ctx := context.Background()

	tokens, err := h.RunAuthorizationCodeFlow(ctx, []string{"openid", "accounts", "offline_access"})
	if err != nil {
		t.Fatalf("RunAuthorizationCodeFlow: %v", err)
	}
	if tokens.AccessToken.Reveal() == "" {
		t.Fatalf("AccessToken is empty")
	}
	if tokens.TokenType != "DPoP" {
		t.Errorf("TokenType = %q, want DPoP", tokens.TokenType)
	}
	if !tokens.HasIDToken || tokens.Subject != fapitest.Subject {
		t.Errorf("HasIDToken=%v Subject=%q, want true/%q", tokens.HasIDToken, tokens.Subject, fapitest.Subject)
	}
	if !tokens.HasRefreshToken {
		t.Errorf("HasRefreshToken = false, want true (offline_access was granted)")
	}

	verifyAccessToken(t, h, tokens)
}

func TestAuthorizationCodeFlowMessageSigning(t *testing.T) {
	h := fapitest.New(t, fapitest.Config{Profile: server.ProfileFAPISecurityWithMessageSigning})
	ctx := context.Background()

	tokens, err := h.RunAuthorizationCodeFlow(ctx, []string{"openid", "accounts"})
	if err != nil {
		t.Fatalf("RunAuthorizationCodeFlow: %v", err)
	}
	if !tokens.HasIDToken || tokens.Subject != fapitest.Subject {
		t.Errorf("HasIDToken=%v Subject=%q, want true/%q", tokens.HasIDToken, tokens.Subject, fapitest.Subject)
	}
	verifyAccessToken(t, h, tokens)
}

func TestAuthorizationCodeFlowScopeWithoutOfflineAccessOmitsRefreshToken(t *testing.T) {
	h := fapitest.New(t, fapitest.Config{Profile: server.ProfileFAPISecurity})
	ctx := context.Background()

	tokens, err := h.RunAuthorizationCodeFlow(ctx, []string{"accounts"})
	if err != nil {
		t.Fatalf("RunAuthorizationCodeFlow: %v", err)
	}
	if tokens.HasRefreshToken {
		t.Errorf("HasRefreshToken = true, want false (offline_access was not requested)")
	}
	if tokens.HasIDToken {
		t.Errorf("HasIDToken = true, want false (openid was not requested)")
	}
}

func TestAuthorizationCodeFlowDeniedInteraction(t *testing.T) {
	// The harness always auto-approves (see AutoApprove), so this test
	// instead exercises the plain "no such request_uri" local-error path
	// by never calling BeginAuthorization at all — confirming
	// CompleteAuthorization surfaces a client-side error rather than a
	// spurious success when the callback never happened.
	h := fapitest.New(t, fapitest.Config{Profile: server.ProfileFAPISecurity})
	_, err := h.RunAuthorizationCodeFlowWithCallback(context.Background(), "state=does-not-exist&code=bogus")
	if err == nil {
		t.Fatalf("RunAuthorizationCodeFlowWithCallback(unknown state) = nil error, want error")
	}
}

// TestAuthorizationCodeFlowAccessTokenExpires proves Harness.Clock —
// shared across the harness's client, server and resource dependencies
// — genuinely drives token-expiry enforcement end to end, not just that
// each role's static configuration is wired up. Clock.Advance itself
// had no test of its own anywhere in this package.
func TestAuthorizationCodeFlowAccessTokenExpires(t *testing.T) {
	h := fapitest.New(t, fapitest.Config{Profile: server.ProfileFAPISecurity})
	ctx := context.Background()

	tokens, err := h.RunAuthorizationCodeFlow(ctx, []string{"openid", "accounts"})
	if err != nil {
		t.Fatalf("RunAuthorizationCodeFlow: %v", err)
	}
	verifyAccessToken(t, h, tokens)

	h.Clock.Advance(6 * time.Minute) // past the harness's 5-minute access token lifetime

	target, err := url.Parse("https://rs.fapitest.internal/accounts")
	if err != nil {
		t.Fatalf("parse target url: %v", err)
	}
	proof, err := h.NewResourceRequestDPoPProof(ctx, "GET", target, tokens.AccessToken.Reveal())
	if err != nil {
		t.Fatalf("NewResourceRequestDPoPProof: %v", err)
	}
	if _, err := h.Resource.Verify(ctx, resource.VerifyRequest{
		Method:        "GET",
		URL:           target,
		Authorization: "DPoP " + tokens.AccessToken.Reveal(),
		DPoPProofs:    []string{proof},
	}); err == nil {
		t.Fatalf("resource.Verify(expired access token) = nil error, want error")
	}
}

// verifyAccessToken drives tokens.AccessToken through resource.Verify
// against a freshly signed DPoP proof bound to the same key the client
// used at token exchange — proving the whole chain (client-issued DPoP
// proof, server-bound cnf.jkt, resource-side verification) is mutually
// consistent end to end, not just that each role's own unit tests pass
// in isolation.
func verifyAccessToken(t *testing.T, h *fapitest.Harness, tokens client.TokenSet) {
	t.Helper()
	ctx := context.Background()
	target, err := url.Parse("https://rs.fapitest.internal/accounts")
	if err != nil {
		t.Fatalf("parse target url: %v", err)
	}

	proof, err := h.NewResourceRequestDPoPProof(ctx, "GET", target, tokens.AccessToken.Reveal())
	if err != nil {
		t.Fatalf("NewResourceRequestDPoPProof: %v", err)
	}

	authz, err := h.Resource.Verify(ctx, resource.VerifyRequest{
		Method:        "GET",
		URL:           target,
		Authorization: "DPoP " + tokens.AccessToken.Reveal(),
		DPoPProofs:    []string{proof},
	})
	if err != nil {
		t.Fatalf("resource.Verify: %v", err)
	}
	if authz.Subject != fapitest.Subject {
		t.Errorf("Subject = %q, want %q", authz.Subject, fapitest.Subject)
	}
	if authz.ClientID != fapitest.ClientID.String() {
		t.Errorf("ClientID = %q, want %q", authz.ClientID, fapitest.ClientID.String())
	}
}

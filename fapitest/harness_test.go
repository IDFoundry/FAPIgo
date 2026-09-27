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

// TestAuthorizationCodeFlowRejectsCallbackFromAnotherSession is the
// login CSRF case (RFC 9700 §4.7) end to end: flow B's genuine callback
// URL, delivered to a browser holding flow A's session, is rejected —
// and flow B still completes normally for its own session afterwards.
func TestAuthorizationCodeFlowRejectsCallbackFromAnotherSession(t *testing.T) {
	h := fapitest.New(t, fapitest.Config{Profile: server.ProfileFAPISecurity})
	ctx := context.Background()

	victim, err := h.Client.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid", "accounts"}})
	if err != nil {
		t.Fatalf("BeginAuthorization (victim): %v", err)
	}
	attacker, err := h.Client.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid", "accounts"}})
	if err != nil {
		t.Fatalf("BeginAuthorization (attacker): %v", err)
	}
	attackerCallback, err := h.CaptureCallback(ctx, attacker)
	if err != nil {
		t.Fatalf("CaptureCallback: %v", err)
	}

	if _, err := h.RunAuthorizationCodeFlowWithCallback(ctx, victim.Handle(), attackerCallback); err == nil {
		t.Fatal("callback from another session completed; want it rejected")
	}
	if _, err := h.RunAuthorizationCodeFlowWithCallback(ctx, attacker.Handle(), attackerCallback); err != nil {
		t.Fatalf("callback with its own session: %v (a rejected mismatch must not consume the session)", err)
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
func verifyAccessToken(t *testing.T, h *fapitest.Harness, tokens client.TokenSet) resource.AuthorizationContext {
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
	return authz
}

// TestAuthorizationCodeFlowLoopbackHTTPRedirectURI covers a client
// registered for a loopback http redirect URI (RFC 8252 §7.3), accepted
// under the harness's AssuranceDevelopment server, through a complete
// flow under both profiles.
func TestAuthorizationCodeFlowLoopbackHTTPRedirectURI(t *testing.T) {
	profiles := map[string]server.Profile{
		"security":        server.ProfileFAPISecurity,
		"message-signing": server.ProfileFAPISecurityWithMessageSigning,
	}
	for name, profile := range profiles {
		t.Run(name, func(t *testing.T) {
			h := fapitest.New(t, fapitest.Config{Profile: profile, RedirectURI: "http://localhost:8080/callback"})

			tokens, err := h.RunAuthorizationCodeFlow(context.Background(), []string{"openid", "accounts"})
			if err != nil {
				t.Fatalf("RunAuthorizationCodeFlow: %v", err)
			}
			verifyAccessToken(t, h, tokens)
		})
	}
}

// TestCaptureCallbackReportsFailures covers CaptureCallback's error
// paths a test can reach: the authorization request failing outright,
// and the authorization endpoint answering without a redirect — here
// because the session's request_uri was already used by an earlier
// capture.
func TestCaptureCallbackReportsFailures(t *testing.T) {
	h := fapitest.New(t, fapitest.Config{Profile: server.ProfileFAPISecurity})
	ctx := context.Background()
	session, err := h.Client.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid", "accounts"}})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := h.CaptureCallback(cancelled, session); err == nil {
		t.Error("CaptureCallback(cancelled context) = nil error, want error")
	}

	if _, err := h.CaptureCallback(ctx, session); err != nil {
		t.Fatalf("CaptureCallback: %v", err)
	}
	if _, err := h.CaptureCallback(ctx, session); err == nil {
		t.Error("CaptureCallback(already used request_uri) = nil error, want error")
	}
}

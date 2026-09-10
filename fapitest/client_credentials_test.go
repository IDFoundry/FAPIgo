package fapitest_test

import (
	"context"
	"net/url"
	"testing"

	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/fapitest"
	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/server"
)

// TestClientCredentialsFlow drives client.Client.RequestClientCredentialsToken
// against a real server.Server over HTTP end to end — the RFC 6749 §4.4
// grant has no browser hop and no prior session, so unlike every other
// flow this harness exercises, there is nothing to complete beyond this
// one call.
func TestClientCredentialsFlow(t *testing.T) {
	h := fapitest.New(t, fapitest.Config{Profile: server.ProfileFAPISecurity, ClientCredentialsGrant: true})
	ctx := context.Background()

	result, err := h.Client.RequestClientCredentialsToken(ctx, client.ClientCredentialsTokenRequest{Scope: []string{"accounts"}})
	if err != nil {
		t.Fatalf("RequestClientCredentialsToken: %v", err)
	}
	if result.AccessToken.Reveal() == "" {
		t.Fatalf("AccessToken is empty")
	}
	if result.TokenType != "DPoP" {
		t.Errorf("TokenType = %q, want DPoP", result.TokenType)
	}
	if result.Scope != "accounts" {
		t.Errorf("Scope = %q, want accounts", result.Scope)
	}
	if !result.HasExpiresIn {
		t.Errorf("HasExpiresIn = false, want true")
	}

	target, err := url.Parse("https://rs.fapitest.internal/accounts")
	if err != nil {
		t.Fatalf("parse target url: %v", err)
	}
	proof, err := h.NewResourceRequestDPoPProof(ctx, "GET", target, result.AccessToken.Reveal())
	if err != nil {
		t.Fatalf("NewResourceRequestDPoPProof: %v", err)
	}
	authz, err := h.Resource.Verify(ctx, resource.VerifyRequest{
		Method:        "GET",
		URL:           target,
		Authorization: "DPoP " + result.AccessToken.Reveal(),
		DPoPProofs:    []string{proof},
	})
	if err != nil {
		t.Fatalf("resource.Verify: %v", err)
	}
	// RFC 9068 §2.2: client_credentials has no end user, so the client
	// is its own subject — see server.RequestClientCredentialsToken's
	// own doc comment.
	if authz.Subject != fapitest.ClientID.String() {
		t.Errorf("Subject = %q, want %q (the client's own ID)", authz.Subject, fapitest.ClientID.String())
	}
	if authz.ClientID != fapitest.ClientID.String() {
		t.Errorf("ClientID = %q, want %q", authz.ClientID, fapitest.ClientID.String())
	}
}

// TestClientCredentialsFlowRejectedWhenNotEnabled confirms
// RequestClientCredentialsToken surfaces the server's own refusal rather
// than succeeding, when the harness's server never enabled the grant —
// the same "disabled means disabled" contract server.Config.ClientCredentialsGrant's
// own doc comment describes.
func TestClientCredentialsFlowRejectedWhenNotEnabled(t *testing.T) {
	h := fapitest.New(t, fapitest.Config{Profile: server.ProfileFAPISecurity})
	ctx := context.Background()

	if _, err := h.Client.RequestClientCredentialsToken(ctx, client.ClientCredentialsTokenRequest{Scope: []string{"accounts"}}); err == nil {
		t.Fatalf("RequestClientCredentialsToken(grant disabled) = nil error, want error")
	}
}

package fapitest_test

import (
	"context"
	"encoding/json"
	"net/url"
	"testing"

	"github.com/osanderson/go-fapi/client"
	"github.com/osanderson/go-fapi/extension"
	"github.com/osanderson/go-fapi/fapitest"
	"github.com/osanderson/go-fapi/resource"
	"github.com/osanderson/go-fapi/server"
)

// accountHintDef is a custom authorization parameter flagged
// ReturnInTokenClaims — it must survive PAR -> authorization code ->
// access token, all the way out to a resource server's own view of the
// token's claims, without server ever being told to do so a second
// time.
var accountHintDef = extension.Definition[string]{
	Name:                "x_account_hint",
	Cardinality:         extension.Single,
	AllowedSources:      extension.SourceRequestObject,
	MaxBytes:            64,
	ReturnInTokenClaims: true,
}

func TestReturnInTokenClaimsPropagatesToIssuedAccessToken(t *testing.T) {
	registry, err := extension.NewRegistry(accountHintDef)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	h := fapitest.New(t, fapitest.Config{
		Profile:    server.ProfileFAPISecurityWithMessageSigning,
		Extensions: registry,
	})
	ctx := context.Background()

	req := client.BeginAuthorizationRequest{Scope: []string{"openid", "accounts"}}
	if err := extension.Set(&req.Extensions, accountHintDef, "acc-789"); err != nil {
		t.Fatalf("extension.Set: %v", err)
	}

	tokens, err := h.RunAuthorizationCodeFlowWithRequest(ctx, req)
	if err != nil {
		t.Fatalf("RunAuthorizationCodeFlowWithRequest: %v", err)
	}

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
		DPoPProof:     proof,
	})
	if err != nil {
		t.Fatalf("resource.Verify: %v", err)
	}

	raw, ok := authz.Claims["x_account_hint"]
	if !ok {
		t.Fatalf("access token claims are missing x_account_hint; got %v", authz.Claims)
	}
	var got string
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal x_account_hint: %v", err)
	}
	if got != "acc-789" {
		t.Errorf("x_account_hint = %q, want acc-789", got)
	}
}

func TestUnregisteredExtensionParameterIsRejectedAtPAR(t *testing.T) {
	// No registry configured at all: every non-core parameter must be
	// rejected, not silently accepted — see server.Config.Extensions.
	h := fapitest.New(t, fapitest.Config{Profile: server.ProfileFAPISecurityWithMessageSigning})
	ctx := context.Background()

	req := client.BeginAuthorizationRequest{Scope: []string{"openid"}}
	if err := extension.Set(&req.Extensions, accountHintDef, "acc-1"); err != nil {
		t.Fatalf("extension.Set: %v", err)
	}

	if _, err := h.RunAuthorizationCodeFlowWithRequest(ctx, req); err == nil {
		t.Fatalf("RunAuthorizationCodeFlowWithRequest(unregistered extension) = nil error, want error")
	}
}

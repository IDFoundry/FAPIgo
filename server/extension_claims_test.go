package server_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	fapi "github.com/osanderson/go-fapi"
	"github.com/osanderson/go-fapi/extension"
	"github.com/osanderson/go-fapi/internal/token"
	"github.com/osanderson/go-fapi/server"
)

// accountHintExtensionDef is a plain-parameter custom authorization
// parameter flagged ReturnInTokenClaims — string-typed, matching the
// constraint documented on server.Config.Extensions: this server's
// plain-parameter path always represents a value as a form-encoded
// string.
var accountHintExtensionDef = extension.Definition[string]{
	Name: "x_account_hint", Cardinality: extension.Single,
	AllowedSources: extension.SourcePlainParameter, MaxBytes: 64,
	ReturnInTokenClaims: true,
}

func TestReturnInTokenClaimsPropagatesThroughAuthorizationCodeGrant(t *testing.T) {
	registry, err := extension.NewRegistry(accountHintExtensionDef)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	h := newHarnessWithExtensions(t, server.ProfileFAPISecurity, registry)

	pushResult, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: plainFormParameters(t, h.clientAssertion(t), map[string]string{
			"x_account_hint": "acc-999",
		})},
	})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}

	action, err := h.server.BeginAuthorization(context.Background(), server.BeginAuthorizationRequest{
		RequestURI: pushResult.RequestURI.String(), ClientID: testClientID,
	})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	interaction, ok := action.(server.InteractionRequired)
	if !ok {
		t.Fatalf("action = %T, want server.InteractionRequired", action)
	}

	subjectID, err := server.NewSubjectID("user-1")
	if err != nil {
		t.Fatalf("NewSubjectID: %v", err)
	}
	subject, err := server.NewAuthenticatedSubject(subjectID)
	if err != nil {
		t.Fatalf("NewAuthenticatedSubject: %v", err)
	}
	authCtx, err := server.NewAuthenticationContext(h.now, "", nil)
	if err != nil {
		t.Fatalf("NewAuthenticationContext: %v", err)
	}
	result, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
		Handle: interaction.Handle,
		Result: server.Authorize(subject, authCtx, server.GrantedAuthorization{Scope: []string{"openid", "accounts"}}),
	})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	redirect, ok := result.(server.AuthorizationRedirect)
	if !ok {
		t.Fatalf("result = %T, want server.AuthorizationRedirect", result)
	}
	dest := redirect.Destination().URL()
	code := dest.Query().Get("code")
	if code == "" {
		t.Fatalf("redirect missing code parameter")
	}

	dpopKey := generateKey(t)
	exchangeResult, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:      server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
		DPoPProof: createDPoPProof(t, dpopKey, h.now),
	})
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}

	parsedAT, err := token.ParseAccessToken(exchangeResult.AccessToken.Reveal())
	if err != nil {
		t.Fatalf("ParseAccessToken: %v", err)
	}
	dpopThumbprint, err := jwkThumbprintFor(dpopKey)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	validatedAT, err := parsedAT.Validate(&h.serverKey.PublicKey, token.AccessTokenValidatePolicy{
		ExpectedIssuer: testIssuer, ExpectedAudience: testIssuer,
		Algorithm: fapi.ES256, ExpectedThumbprint: &dpopThumbprint,
		Now: h.now, MaxLifetime: 10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Validate access token: %v", err)
	}

	raw, ok := validatedAT.Parameters["x_account_hint"]
	if !ok {
		t.Fatalf("access token claims are missing x_account_hint; got %v", validatedAT.Parameters)
	}
	var got string
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal x_account_hint: %v", err)
	}
	if got != "acc-999" {
		t.Fatalf("x_account_hint = %q, want acc-999", got)
	}
}

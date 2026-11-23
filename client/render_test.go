package client_test

import (
	"context"
	"testing"

	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/internal/pkce"
	"github.com/idfoundry/fapigo/internal/rendertest"
)

// flowCode is the authorization code the fake AS answers the flow with.
const flowCode = "AUTH-CODE-FROM-THE-AS-0042"

// TestFlowResultsPrintNoSecret runs a real authorization code flow
// against the fake authorization server, then renders every result it
// produced, with the values the flow carried on the wire as sentinels:
// the code, PKCE verifier, nonce and session handle, then the tokens.
// None prints, except where a type keeps its wire value on purpose: a
// SessionHandle's String, and the validated nonce in IDTokenClaims.
func TestFlowResultsPrintNoSecret(t *testing.T) {
	ctx := context.Background()
	c, as, _ := newTestClient(t, false)
	session, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid"}})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	cb := client.AuthorizationCallback{RawQuery: as.callbackFor(t, as.lastState, flowCode, ""), Session: session.Handle()}
	result, err := c.HandleAuthorizationResponse(ctx, cb)
	if err != nil {
		t.Fatalf("HandleAuthorizationResponse: %v", err)
	}
	success, ok := result.(client.CallbackSuccess)
	if !ok {
		t.Fatalf("result = %T, want client.CallbackSuccess", result)
	}
	tokens, err := c.ExchangeCode(ctx, success.Response)
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}

	// The code and verifier reach the token endpoint intact, and the
	// verifier is the one the pushed request's code_challenge commits to.
	verifier := as.lastTokenForm.Get("code_verifier")
	if challenge, err := pkce.Challenge(verifier, pkce.S256); err != nil || challenge != as.lastPARForm.Get("code_challenge") || as.lastTokenForm.Get("code") != flowCode {
		t.Fatalf("token request carried code %q and a verifier whose challenge is %q (%v); the pushed request committed to %q",
			as.lastTokenForm.Get("code"), challenge, err, as.lastPARForm.Get("code_challenge"))
	}

	handle := session.Handle().String()
	rendertest.Check(t, success, []string{flowCode, verifier, as.lastNonce, handle}, rendertest.Quick())
	rendertest.Check(t, session, []string{handle}, rendertest.Quick())
	rendertest.Check(t, cb, []string{handle}, rendertest.Quick())
	bearer := []string{tokens.AccessToken.Reveal(), tokens.IDToken.Reveal(), tokens.RefreshToken.Reveal()}
	rendertest.Check(t, tokens, bearer, rendertest.Quick())
	rendertest.Check(t, c.ProtectedResource(tokens), bearer[:1], rendertest.Quick())
}

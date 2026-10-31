package server_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// rarHTMLObject is a payment detail object full of the characters
// encoding/json escapes as HTML ('<', '>', '&' become six-byte \u003c
// escapes, and U+2028 a six-byte \u2028 one), so re-encoding it with
// json.Marshal would grow it well past the bound below.
var rarHTMLObject = `{"type":"payment","actions":["approve"],"amount":"` + strings.Repeat("<>&", 20) + "\u2028" + `"}`

// rarHTMLHarness registers "payment" with a MaxBytesPerObject only just
// above rarHTMLObject's own size, and a total bound only just above the
// one-object array's.
func rarHTMLHarness(t *testing.T) harness {
	t.Helper()
	def := extension.RARDefinition[testPaymentDetail]{
		Type: "payment", MaxObjects: 1, MaxBytesPerObject: len(rarHTMLObject) + 8,
	}
	registry, err := extension.NewRARRegistry(len(rarHTMLObject)+16, 4, def)
	if err != nil {
		t.Fatalf("NewRARRegistry: %v", err)
	}
	allow := fakeRARPolicy{allow: map[string]bool{"payment": true}}
	return newHarnessWithRAR(t, server.ProfileFAPISecurity, registry, allow, allow)
}

// rarHTMLIssueCode pushes a request for exactly rarHTMLObject, grants it
// as the end user was shown it, and returns the authorization code.
func rarHTMLIssueCode(t *testing.T, h harness) string {
	t.Helper()
	push, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_assertion", h.clientAssertion(t)),
			formParam("client_assertion_type", clientassertion.AssertionType),
			formParam("response_type", "code"),
			formParam("redirect_uri", testRedirectURI),
			formParam("scope", "openid accounts offline_access"),
			formParam("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
			formParam("code_challenge_method", "S256"),
			formParam("state", "opaque-state"),
			formParam("authorization_details", "["+rarHTMLObject+"]"),
		}},
	})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
	action, err := h.server.BeginAuthorization(context.Background(), server.BeginAuthorizationRequest{RequestURI: push.RequestURI.String(), ClientID: testClientID})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	interaction := action.(server.InteractionRequired)
	shown, err := json.Marshal(interaction.Interaction.AuthorizationDetails)
	if err != nil {
		t.Fatalf("marshal shown authorization_details: %v", err)
	}
	var shownObjects []json.RawMessage
	if err := json.Unmarshal(shown, &shownObjects); err != nil || len(shownObjects) != 1 {
		t.Fatalf("end user was shown authorization_details %s, want the one requested object", shown)
	}
	subject, authCtx := rarSubjectAndAuthCtx(t, h.now)
	result, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
		Handle: interaction.Handle,
		Result: server.Authorize(subject, authCtx, server.GrantedAuthorization{
			Scope:                []string{"openid", "accounts", "offline_access"},
			AuthorizationDetails: []json.RawMessage{json.RawMessage(rarHTMLObject)},
		}),
	})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	redirect, ok := result.(server.AuthorizationRedirect)
	if !ok {
		t.Fatalf("CompleteAuthorization = %T, want AuthorizationRedirect", result)
	}
	dest := redirect.Destination().URL()
	code := dest.Query().Get("code")
	if code == "" {
		t.Fatalf("CompleteAuthorization redirected to %s, want a code", dest.String())
	}
	return code
}

// assertRARHTMLIssued checks the token response and the access token's
// claim both carry the granted object byte for byte, not re-escaped.
func assertRARHTMLIssued(t *testing.T, h harness, result server.TokenResult) {
	t.Helper()
	want := "[" + rarHTMLObject + "]"
	if got := string(result.AuthorizationDetails); got != want {
		t.Errorf("TokenResult.AuthorizationDetails = %s, want %s", got, want)
	}
	claim := authorizationDetailsAccessTokenClaim(t, result.AccessToken.Reveal(), &h.serverKey.PublicKey)
	if got := string(claim); got != want {
		t.Errorf("access token authorization_details claim = %s, want %s", got, want)
	}
}

// TestAuthorizationDetailsKeepTheirBytesThroughGrantAndRefresh: details a
// client requested within Config.RAR's size bounds stay within them once
// granted, stored and refreshed. encoding/json escapes '<', '>', '&',
// U+2028 and U+2029 when it re-encodes, growing each to six bytes, so a
// grant re-encoded that way could be refused at consent, or by the
// refresh-time re-check, as too large — and its tokens would carry bytes
// other than the ones validated.
func TestAuthorizationDetailsKeepTheirBytesThroughGrantAndRefresh(t *testing.T) {
	h := rarHTMLHarness(t)
	first, err := rarExchangeCode(t, h, rarHTMLIssueCode(t, h), nil)
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	assertRARHTMLIssued(t, h, first)
	if !first.HasRefreshToken {
		t.Fatal("no refresh token issued")
	}
	refreshToken := first.RefreshToken.Reveal()

	for name, details := range map[string]*string{"absent": nil, "narrowed to the same object": rarParam("[" + rarHTMLObject + "]")} {
		t.Run(name, func(t *testing.T) {
			refreshed, err := rarRefresh(t, h, refreshToken, details)
			if err != nil {
				t.Fatalf("RefreshAccessToken: %v", err)
			}
			assertRARHTMLIssued(t, h, refreshed)
		})
	}
}

// TestEmbedderAuthorizationDetailsKeepTheirBytes is
// TestAuthorizationDetailsKeepTheirBytesThroughGrantAndRefresh for
// details an embedder grants itself (IssueRefreshTokenRequest.AuthorizationDetails).
func TestEmbedderAuthorizationDetailsKeepTheirBytes(t *testing.T) {
	def := extension.RARDefinition[testPaymentDetail]{
		Type: "payment", MaxObjects: 1, MaxBytesPerObject: len(rarHTMLObject) + 8,
	}
	registry, err := extension.NewRARRegistry(len(rarHTMLObject)+16, 4, def)
	if err != nil {
		t.Fatalf("NewRARRegistry: %v", err)
	}
	attesterKey := generateKey(t)
	h := newAttestationHarness(t, time.Now(), attesterKey, server.RegisteredAttesterKeys{}, func(cfg *server.Config, c *storage.RegisteredClientConfig) {
		cfg.AdditionalGrantTypes = []string{preAuthorizedCodeGrant}
		cfg.RAR = registry
		c.AllowedScopes = []string{"openid", "accounts"}
		c.AuthorizationDetailsTypes = []string{"payment"}
	})
	instance := &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}
	attested, binding := embedderTokenRequest(t, instance)

	refreshToken, err := h.server.IssueRefreshToken(context.Background(), server.IssueRefreshTokenRequest{
		GrantType: preAuthorizedCodeGrant, Client: attested, Binding: binding,
		Subject: mustSubjectID(t, "holder-1"), Scope: []string{"accounts"},
		AuthorizationDetails: []json.RawMessage{json.RawMessage(rarHTMLObject)},
	})
	if err != nil {
		t.Fatalf("IssueRefreshToken: %v", err)
	}
	result, err := instance.refresh(refreshToken.Reveal())
	if err != nil {
		t.Fatalf("RefreshAccessToken: %v", err)
	}
	assertRARHTMLIssued(t, h, result)
}

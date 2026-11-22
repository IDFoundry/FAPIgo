package fapitest_test

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/fapitest"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// These tests cover a user's plain-mode authorization response leaking
// (a logged callback URL, say) to an attacker, who delivers its code to
// the client in a sign-in of their own: the attacker starts that sign-in
// at the same client, reads their own state from the redirect back, and
// requests the client's callback with the user's code, that state and
// the issuer. The client exchanges the code as it would the user's,
// with the same client authentication, redirect URI and DPoP key, but
// the attacker's sign-in's code_verifier, so the authorization server
// finds no code: it neither spends it nor revokes what it issued.

// signIn runs a user's sign-in at h's client, granting offline_access,
// and returns the callback query the user's browser delivered — what a
// leaked callback URL holds — and the tokens the client got.
func signIn(t *testing.T, h *fapitest.Harness) (callback string, tokens client.TokenSet) {
	t.Helper()
	ctx := context.Background()
	session, err := h.Client.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: offlineScope})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	callback, err = h.CaptureCallback(ctx, session)
	if err != nil {
		t.Fatalf("CaptureCallback: %v", err)
	}
	tokens, err = h.RunAuthorizationCodeFlowWithCallback(ctx, session.Handle(), callback)
	if err != nil {
		t.Fatalf("the user's sign-in: %v", err)
	}
	return callback, tokens
}

// callbackQuery is callback's parameters.
func callbackQuery(t *testing.T, callback string) url.Values {
	t.Helper()
	q, err := url.ParseQuery(callback)
	if err != nil {
		t.Fatalf("ParseQuery(%q): %v", callback, err)
	}
	return q
}

// deliverInOwnSignIn is the attacker delivering code to h's client in a
// sign-in of their own, and returns the client's answer.
func deliverInOwnSignIn(t *testing.T, h *fapitest.Harness, code string) error {
	t.Helper()
	ctx := context.Background()
	session, err := h.Client.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: offlineScope})
	if err != nil {
		t.Fatalf("the attacker's BeginAuthorization: %v", err)
	}
	own, err := h.CaptureCallback(ctx, session)
	if err != nil {
		t.Fatalf("the attacker's CaptureCallback: %v", err)
	}
	q := callbackQuery(t, own)
	delivered := url.Values{"code": {code}, "state": {q.Get("state")}, "iss": {q.Get("iss")}}
	_, err = h.RunAuthorizationCodeFlowWithCallback(ctx, session.Handle(), delivered.Encode())
	return err
}

// TestLeakedCodeDeliveredToItsClientRevokesNothing covers the delivery
// after the code's lifetime, once the user has refreshed: the client
// gets invalid_grant, and the user's refreshed access token and refresh
// token keep working, under either sender constraint.
func TestLeakedCodeDeliveredToItsClientRevokesNothing(t *testing.T) {
	for name, cfg := range map[string]fapitest.Config{
		"private_key_jwt and DPoP": {Profile: server.ProfileFAPISecurity},
		"mTLS": {
			Profile: server.ProfileFAPISecurity, SenderConstrain: storage.SenderConstrainMTLS,
			ClientAuthMethod: storage.ClientAuthMethodSelfSignedTLSClientAuth,
		},
	} {
		t.Run(name, func(t *testing.T) {
			requireDeliveredCodeRevokesNothing(t, fapitest.New(t, cfg))
		})
	}
}

func requireDeliveredCodeRevokesNothing(t *testing.T, h *fapitest.Harness) {
	t.Helper()
	ctx := context.Background()
	callback, first := signIn(t, h)
	h.Clock.Advance(3 * time.Minute) // the code lives a minute, its tokens five
	refreshed, err := h.Client.RefreshTokens(ctx, client.RefreshTokenRequest{Tokens: first})
	if err != nil {
		t.Fatalf("RefreshTokens: %v", err)
	}

	if err := deliverInOwnSignIn(t, h, callbackQuery(t, callback).Get("code")); serverErrorCodeOf(err) != "invalid_grant" {
		t.Fatalf("the delivered code = %v, want the authorization server's invalid_grant", err)
	}
	verifyBoundAccessToken(t, h, refreshed)
	if _, err := h.Client.RefreshTokens(ctx, client.RefreshTokenRequest{Tokens: refreshed}); err != nil {
		t.Fatalf("RefreshTokens after the delivered code: %v", err)
	}
}

// TestLeakedCodeDeliveredToItsClientIsNotSpent covers the delivery
// before the user's own callback is handled: the code isn't spent, so
// the user's sign-in still completes.
func TestLeakedCodeDeliveredToItsClientIsNotSpent(t *testing.T) {
	h := fapitest.New(t, fapitest.Config{Profile: server.ProfileFAPISecurity})
	ctx := context.Background()
	session, err := h.Client.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: offlineScope})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	callback, err := h.CaptureCallback(ctx, session)
	if err != nil {
		t.Fatalf("CaptureCallback: %v", err)
	}
	if err := deliverInOwnSignIn(t, h, callbackQuery(t, callback).Get("code")); serverErrorCodeOf(err) != "invalid_grant" {
		t.Fatalf("the delivered code = %v, want the authorization server's invalid_grant", err)
	}
	if _, err := h.RunAuthorizationCodeFlowWithCallback(ctx, session.Handle(), callback); err != nil {
		t.Fatalf("the user's sign-in after the delivered code: %v", err)
	}
}

// TestClientExchangingItsCodeAgainRevokesItsTokens is the contrast: the
// client exchanging the user's own validated response a second time
// presents the code with its own code_verifier, which is a reuse (RFC
// 6749 §4.1.2), so the tokens it issued are revoked.
func TestClientExchangingItsCodeAgainRevokesItsTokens(t *testing.T) {
	h := fapitest.New(t, fapitest.Config{Profile: server.ProfileFAPISecurity})
	ctx := context.Background()
	session, err := h.Client.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: offlineScope})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	callback, err := h.CaptureCallback(ctx, session)
	if err != nil {
		t.Fatalf("CaptureCallback: %v", err)
	}
	result, err := h.Client.HandleAuthorizationResponse(ctx, client.AuthorizationCallback{RawQuery: callback, Session: session.Handle()})
	if err != nil {
		t.Fatalf("HandleAuthorizationResponse: %v", err)
	}
	validated, ok := result.(client.CallbackSuccess)
	if !ok {
		t.Fatalf("HandleAuthorizationResponse = %T, want CallbackSuccess", result)
	}
	tokens, err := h.Client.ExchangeCode(ctx, validated.Response)
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if _, err := h.Client.ExchangeCode(ctx, validated.Response); serverErrorCodeOf(err) != "invalid_grant" {
		t.Fatalf("ExchangeCode again = %v, want invalid_grant", err)
	}
	if _, err := h.Client.RefreshTokens(ctx, client.RefreshTokenRequest{Tokens: tokens}); serverErrorCodeOf(err) != "invalid_grant" {
		t.Fatalf("RefreshTokens after the code's reuse = %v, want invalid_grant", err)
	}
}

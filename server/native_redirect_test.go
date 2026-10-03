package server_test

import (
	"context"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

const testPrivateUseRedirectURI = "org.idfoundry.oid4vcgo.demowallet:/callback"

// completeWith pushes redirectURI, begins and approves the
// authorization, and returns the response's query, checking it went to
// wantDestination.
func completeWith(t *testing.T, h harness, redirectURI, wantDestination string) map[string][]string {
	t.Helper()
	handle := beginInteractionWithRedirectURI(t, h, redirectURI)
	result, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
		Handle: handle, Result: authorizeResult(t),
	})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	return assertRedirectsTo(t, result, wantDestination)
}

// TestNativeClientPrivateUseRedirectUnderProduction covers RFC 8252
// §7.1 for a native client, in production: the authorization response
// goes to the app's private-use URI with code, state and iss.
func TestNativeClientPrivateUseRedirectUnderProduction(t *testing.T) {
	h := newHarnessWithApplicationType(t, server.ProfileFAPISecurity, true, testPrivateUseRedirectURI, server.AssuranceProduction, storage.ApplicationTypeNative)
	q := completeWith(t, h, testPrivateUseRedirectURI, testPrivateUseRedirectURI)
	for _, name := range []string{"code", "state", "iss"} {
		if len(q[name]) != 1 || q[name][0] == "" {
			t.Errorf("response query = %v, want %s", q, name)
		}
	}
}

// TestNativeClientLoopbackAnyPortUnderProduction covers RFC 8252 §7.3:
// a native client registered for http://127.0.0.1/callback is redirected
// to the port its request names, in production.
func TestNativeClientLoopbackAnyPortUnderProduction(t *testing.T) {
	h := newHarnessWithApplicationType(t, server.ProfileFAPISecurity, true, "http://127.0.0.1/callback", server.AssuranceProduction, storage.ApplicationTypeNative)
	q := completeWith(t, h, "http://127.0.0.1:51004/callback", "http://127.0.0.1:51004/callback")
	if len(q["code"]) != 1 {
		t.Fatalf("response query = %v, want a code", q)
	}
	// The token request names the redirect_uri the authorization request
	// did (RFC 6749 §4.1.3), port and all: the registered form without
	// one isn't it.
	exchange := func(redirectURI string) error {
		_, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
			HTTP:       server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), q["code"][0], redirectURI, testCodeVerifier)},
			DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
		})
		return err
	}
	if err := exchange("http://127.0.0.1/callback"); err == nil {
		t.Error("ExchangeAuthorizationCode(the registered URI, without the request's port) = nil error")
	}
	// The refused exchange may have used up that code: authorize again for
	// the one that should succeed.
	q = completeWith(t, h, "http://127.0.0.1:51004/callback", "http://127.0.0.1:51004/callback")
	if err := exchange("http://127.0.0.1:51004/callback"); err != nil {
		t.Errorf("ExchangeAuthorizationCode(the request's redirect_uri) = %v", err)
	}
}

// TestWebClientRefusedNativeRedirects covers a web client registered for
// the same redirect URIs: none is usable, under production.
func TestWebClientRefusedNativeRedirects(t *testing.T) {
	for name, tc := range map[string]struct{ registered, requested string }{
		"private-use scheme":      {testPrivateUseRedirectURI, testPrivateUseRedirectURI},
		"loopback, any port":      {"http://127.0.0.1/callback", "http://127.0.0.1:51004/callback"},
		"loopback, as registered": {"http://127.0.0.1/callback", "http://127.0.0.1/callback"},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarnessWithApplicationType(t, server.ProfileFAPISecurity, true, tc.registered, server.AssuranceProduction, storage.ApplicationTypeWeb)
			_, err := pushWithRedirectURI(t, h, tc.requested)
			if code := serverErrorCode(t, err); code != server.ErrorInvalidRequest {
				t.Fatalf("PushAuthorizationRequest(%q) error code = %q, want %q", tc.requested, code, server.ErrorInvalidRequest)
			}
		})
	}
}

// TestNativeClientPrivateUseRedirectWithJARM covers Message Signing's
// signed authorization response (JARM) to a private-use URI.
func TestNativeClientPrivateUseRedirectWithJARM(t *testing.T) {
	h := newHarnessWithApplicationType(t, server.ProfileFAPISecurityWithMessageSigning, true, testPrivateUseRedirectURI, server.AssuranceProduction, storage.ApplicationTypeNative)
	params := standardAuthParams(t)
	params["redirect_uri"] = jsonRaw(t, testPrivateUseRedirectURI)
	pushResult, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_assertion", h.clientAssertion(t)),
			formParam("client_assertion_type", clientassertion.AssertionType),
			formParam("request", h.requestObject(t, params)),
		}},
	})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
	action, err := h.server.BeginAuthorization(context.Background(), server.BeginAuthorizationRequest{RequestURI: pushResult.RequestURI.String(), ClientID: testClientID})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	required, ok := action.(server.InteractionRequired)
	if !ok {
		t.Fatalf("action = %T, want server.InteractionRequired", action)
	}
	result, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{Handle: required.Handle, Result: authorizeResult(t)})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	if q := assertRedirectsTo(t, result, testPrivateUseRedirectURI); len(q["response"]) != 1 {
		t.Errorf("response query = %v, want a JARM response", q)
	}
}

// TestBuildAuthorizationErrorRedirectHoldsTheRedirectPolicy covers the
// error redirect a caller builds without a pushed authorization request:
// it gets the same redirect policy PAR applies. Under production, a web
// client's registered loopback or private-use URI is refused; a native
// client's is accepted.
func TestBuildAuthorizationErrorRedirectHoldsTheRedirectPolicy(t *testing.T) {
	for name, tc := range map[string]struct {
		uri     string
		appType storage.ApplicationType
		ok      bool
	}{
		"web, loopback":       {"http://127.0.0.1/callback", storage.ApplicationTypeWeb, false},
		"web, localhost":      {"http://localhost/callback", storage.ApplicationTypeWeb, false},
		"web, private-use":    {testPrivateUseRedirectURI, storage.ApplicationTypeWeb, false},
		"native, private-use": {testPrivateUseRedirectURI, storage.ApplicationTypeNative, true},
		"native, loopback":    {"http://127.0.0.1/callback", storage.ApplicationTypeNative, true},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarnessWithApplicationType(t, server.ProfileFAPISecurity, true, testRedirectURI, server.AssuranceProduction, storage.ApplicationTypeWeb)
			client, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
				ID: testClientID, RedirectURIs: []fapi.RegisteredRedirectURI{fapi.RegisteredRedirectURI(tc.uri)},
				ClientAssertionAlgorithm: fapi.ES256, AllowedScopes: []string{"openid"}, ApplicationType: tc.appType,
			})
			if err != nil {
				t.Fatalf("NewRegisteredClient: %v", err)
			}
			_, err = h.server.BuildAuthorizationErrorRedirect(context.Background(), client, tc.uri, "s", "access_denied", "")
			if got := err == nil; got != tc.ok {
				t.Errorf("BuildAuthorizationErrorRedirect(%q) = %v, want accepted %v", tc.uri, err, tc.ok)
			}
		})
	}
}

// TestPARNamesTheNativeRegistration covers the refusal a native app's
// integrator meets first — a native redirect URI on a client registered
// as web — naming the registration that admits it, for the logs.
func TestPARNamesTheNativeRegistration(t *testing.T) {
	h := newHarnessWithApplicationType(t, server.ProfileFAPISecurity, true, testPrivateUseRedirectURI, server.AssuranceProduction, storage.ApplicationTypeWeb)
	_, err := pushWithRedirectURI(t, h, testPrivateUseRedirectURI)
	if code := serverErrorCode(t, err); code != server.ErrorInvalidRequest {
		t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidRequest)
	}
	if !strings.Contains(err.Error(), "ApplicationTypeNative") {
		t.Errorf("cause = %v, want it to name ApplicationTypeNative", err)
	}
	h = newHarnessWithApplicationType(t, server.ProfileFAPISecurity, true, "http://rp.example/callback", server.AssuranceProduction, storage.ApplicationTypeWeb)
	if _, err := pushWithRedirectURI(t, h, "http://rp.example/callback"); err == nil || strings.Contains(err.Error(), "ApplicationTypeNative") {
		t.Errorf("cause = %v, want no native hint for a URI no registration admits", err)
	}
}

package server_test

import (
	"context"
	"encoding/json"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

const testLoopbackRedirectURI = "http://localhost:8080/callback"

// pushWithRedirectURI pushes a plain authorization request naming
// redirectURI in place of plainFormParameters' own testRedirectURI.
func pushWithRedirectURI(t *testing.T, h harness, redirectURI string) (server.PushAuthorizationResult, error) {
	t.Helper()
	params := plainFormParameters(t, h.clientAssertion(t), nil)
	for i := range params {
		if params[i].Name == "redirect_uri" {
			params[i].Value = redirectURI
		}
	}
	return h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: params},
	})
}

func beginInteractionWithRedirectURI(t *testing.T, h harness, redirectURI string) server.InteractionHandle {
	t.Helper()
	pushResult, err := pushWithRedirectURI(t, h, redirectURI)
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
	action, err := h.server.BeginAuthorization(context.Background(), server.BeginAuthorizationRequest{
		RequestURI: pushResult.RequestURI.String(),
		ClientID:   testClientID,
	})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	required, ok := action.(server.InteractionRequired)
	if !ok {
		t.Fatalf("action = %T, want server.InteractionRequired", action)
	}
	return required.Handle
}

// assertRedirectsTo checks result is a redirect whose destination,
// query string aside, is exactly redirectURI.
func assertRedirectsTo(t *testing.T, result server.AuthorizationResult, redirectURI string) map[string][]string {
	t.Helper()
	redirect, ok := result.(server.AuthorizationRedirect)
	if !ok {
		t.Fatalf("result = %T, want server.AuthorizationRedirect", result)
	}
	dest := redirect.Destination().URL()
	q := dest.Query()
	dest.RawQuery = ""
	if dest.String() != redirectURI {
		t.Fatalf("Destination = %q, want %q", dest.String(), redirectURI)
	}
	return q
}

func TestLoopbackHTTPRedirectURISuccessUnderDevelopment(t *testing.T) {
	h := newHarnessWithRedirectURI(t, server.ProfileFAPISecurity, true, testLoopbackRedirectURI, server.AssuranceDevelopment)
	handle := beginInteractionWithRedirectURI(t, h, testLoopbackRedirectURI)

	result, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
		Handle: handle, Result: authorizeResult(t),
	})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	q := assertRedirectsTo(t, result, testLoopbackRedirectURI)
	if len(q["code"]) != 1 || q["code"][0] == "" {
		t.Fatalf("Destination query = %v, want a code parameter", q)
	}
}

func TestLoopbackHTTPRedirectURIDenyUnderDevelopment(t *testing.T) {
	h := newHarnessWithRedirectURI(t, server.ProfileFAPISecurity, true, testLoopbackRedirectURI, server.AssuranceDevelopment)
	handle := beginInteractionWithRedirectURI(t, h, testLoopbackRedirectURI)

	result, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
		Handle: handle, Result: server.Deny("user declined consent"),
	})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	q := assertRedirectsTo(t, result, testLoopbackRedirectURI)
	if got := q["error"]; len(got) != 1 || got[0] != "access_denied" {
		t.Fatalf("error = %v, want access_denied", got)
	}
}

func TestLoopbackHTTPRedirectURIMessageSigningUnderDevelopment(t *testing.T) {
	h := newHarnessWithRedirectURI(t, server.ProfileFAPISecurityWithMessageSigning, true, testLoopbackRedirectURI, server.AssuranceDevelopment)
	requestObj := h.requestObject(t, loopbackAuthParams(t))
	pushResult, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_assertion", h.clientAssertion(t)),
			formParam("client_assertion_type", clientassertion.AssertionType),
			formParam("request", requestObj),
		}},
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
	required, ok := action.(server.InteractionRequired)
	if !ok {
		t.Fatalf("action = %T, want server.InteractionRequired", action)
	}
	result, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
		Handle: required.Handle, Result: authorizeResult(t),
	})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	q := assertRedirectsTo(t, result, testLoopbackRedirectURI)
	if len(q["response"]) != 1 {
		t.Fatalf("Destination query = %v, want a JARM response parameter", q)
	}
}

func loopbackAuthParams(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	params := standardAuthParams(t)
	params["redirect_uri"] = jsonRaw(t, testLoopbackRedirectURI)
	return params
}

func TestBuildAuthorizationErrorRedirectLoopbackHTTPUnderDevelopment(t *testing.T) {
	h := newHarnessWithRedirectURI(t, server.ProfileFAPISecurity, true, testLoopbackRedirectURI, server.AssuranceDevelopment)
	client, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID:                       testClientID,
		RedirectURIs:             []fapi.RegisteredRedirectURI{testLoopbackRedirectURI},
		ClientAssertionAlgorithm: fapi.ES256,
		AllowedScopes:            []string{"openid"},
	})
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}

	dest, err := h.server.BuildAuthorizationErrorRedirect(context.Background(), client, testLoopbackRedirectURI, "s", "invalid_request", "bad request")
	if err != nil {
		t.Fatalf("BuildAuthorizationErrorRedirect: %v", err)
	}
	u := dest.URL()
	u.RawQuery = ""
	if u.String() != testLoopbackRedirectURI {
		t.Fatalf("destination = %q, want %q", u.String(), testLoopbackRedirectURI)
	}
}

// TestPushAuthorizationRequestRejectsUnacceptableRedirectURI covers the
// redirect URIs a client may be registered for but that can never be
// redirected to: each is refused at PAR as invalid_request, rather than
// accepted there and failing with server_error once the flow completes.
func TestPushAuthorizationRequestRejectsUnacceptableRedirectURI(t *testing.T) {
	cases := []struct {
		name        string
		redirectURI string
		assurance   server.AssuranceLevel
	}{
		{"non-loopback http under development", "http://rp.example/callback", server.AssuranceDevelopment},
		{"private-use scheme under development", "com.example.app:/callback", server.AssuranceDevelopment},
		{"loopback http under production", testLoopbackRedirectURI, server.AssuranceProduction},
		{"loopback IP http under production", "http://127.0.0.1:8080/callback", server.AssuranceProduction},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarnessWithRedirectURI(t, server.ProfileFAPISecurity, true, tc.redirectURI, tc.assurance)
			_, err := pushWithRedirectURI(t, h, tc.redirectURI)
			if err == nil {
				t.Fatalf("PushAuthorizationRequest(%q) = nil error, want invalid_request", tc.redirectURI)
			}
			if code := serverErrorCode(t, err); code != server.ErrorInvalidRequest {
				t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidRequest)
			}
		})
	}
}

func TestPushAuthorizationRequestAcceptsHTTPSRedirectURIUnderProduction(t *testing.T) {
	h := newHarnessWithRedirectURI(t, server.ProfileFAPISecurity, true, testRedirectURI, server.AssuranceProduction)
	if _, err := pushWithRedirectURI(t, h, testRedirectURI); err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
}

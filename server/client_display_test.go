package server_test

import (
	"context"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

func TestBeginAuthorizationCarriesClientDisplay(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	logo, err := fapi.ParseEndpointURL("https://client.example/logo.png")
	if err != nil {
		t.Fatal(err)
	}
	client, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID:                       testClientID,
		RedirectURIs:             []fapi.RegisteredRedirectURI{testRedirectURI},
		ClientAssertionAlgorithm: fapi.ES256,
		RequestObjectAlgorithm:   fapi.ES256,
		AllowedScopes:            []string{"openid", "accounts", "offline_access"},
		Display:                  storage.ClientDisplay{Name: "Example Client", LogoURI: logo},
	})
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}
	h.clients.clients[testClientID] = client

	required, ok := pushAndBegin(t, h, nil).(server.InteractionRequired)
	if !ok {
		t.Fatal("BeginAuthorization didn't require interaction")
	}
	if got := required.Interaction.ClientDisplay; got.Name != "Example Client" || got.LogoURI.String() != logo.String() {
		t.Errorf("ClientDisplay = %+v, want the registered name and logo", got)
	}
}

// TestBeginAuthorizationRefusesClientNoLongerRegistered covers a client
// that stops resolving between its pushed authorization request and the
// browser arriving — e.g. a federation member whose Trust Chain no
// longer holds. There's nothing to show on a consent screen, and no
// consent should be collected for it.
func TestBeginAuthorizationRefusesClientNoLongerRegistered(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	ctx := context.Background()
	pushed, err := h.server.PushAuthorizationRequest(ctx, server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: plainFormParameters(t, h.clientAssertion(t), nil)},
	})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
	delete(h.clients.clients, testClientID)

	action, err := h.server.BeginAuthorization(ctx, server.BeginAuthorizationRequest{RequestURI: pushed.RequestURI.String(), ClientID: testClientID})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	local, ok := action.(server.LocalErrorResponse)
	if !ok {
		t.Fatalf("action = %T, want server.LocalErrorResponse", action)
	}
	if local.Error.Code() != server.ErrorUnauthorizedClient {
		t.Errorf("Code = %q, want %q", local.Error.Code(), server.ErrorUnauthorizedClient)
	}
}

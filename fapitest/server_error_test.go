package fapitest_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/fapitest"
	"github.com/idfoundry/fapigo/server"
)

// These tests check client.Error.ServerResponse against the real
// server's own error responses, over HTTP, for each endpoint that
// carries one.

func requireServerResponse(t *testing.T, err error, code string, status int) {
	t.Helper()
	var cerr *client.Error
	if !errors.As(err, &cerr) {
		t.Fatalf("error = %v (%T), want *client.Error", err, err)
	}
	got, ok := cerr.ServerResponse()
	if !ok || got.Code != code || got.HTTPStatus != status {
		t.Fatalf("ServerResponse() = %+v, %v, want code %q and status %d", got, ok, code, status)
	}
}

func TestServerResponseFromPushedAuthorizationRequest(t *testing.T) {
	h := fapitest.New(t, fapitest.Config{Profile: server.ProfileFAPISecurity})
	_, err := h.Client.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{Scope: []string{"openid", "not_registered"}})
	if err == nil {
		t.Fatal("BeginAuthorization(unregistered scope) = nil error, want error")
	}
	requireServerResponse(t, err, "invalid_scope", http.StatusBadRequest)
}

func TestServerResponseFromTokenEndpoint(t *testing.T) {
	h := fapitest.New(t, fapitest.Config{Profile: server.ProfileFAPISecurity})
	ctx := context.Background()
	session, err := h.Client.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid", "accounts"}})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	callback, err := h.CaptureCallback(ctx, session)
	if err != nil {
		t.Fatalf("CaptureCallback: %v", err)
	}
	h.Clock.Advance(2 * time.Minute) // past the harness's 1-minute authorization code lifetime

	_, err = h.RunAuthorizationCodeFlowWithCallback(ctx, session.Handle(), callback)
	if err == nil {
		t.Fatal("RunAuthorizationCodeFlowWithCallback(expired code) = nil error, want error")
	}
	requireServerResponse(t, err, "invalid_grant", http.StatusBadRequest)
}

func TestServerResponseFromUserInfo(t *testing.T) {
	h := fapitest.New(t, fapitest.Config{Profile: server.ProfileFAPISecurity})
	ctx := context.Background()
	tokens, err := h.RunAuthorizationCodeFlow(ctx, []string{"openid", "accounts"})
	if err != nil {
		t.Fatalf("RunAuthorizationCodeFlow: %v", err)
	}
	h.Clock.Advance(6 * time.Minute) // past the harness's 5-minute access token lifetime

	_, err = h.Client.FetchUserInfo(ctx, tokens)
	if err == nil {
		t.Fatal("FetchUserInfo(expired access token) = nil error, want error")
	}
	requireServerResponse(t, err, "invalid_token", http.StatusUnauthorized)
}

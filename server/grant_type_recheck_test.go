package server_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// reregisterTestClient replaces testClientID's registration in h with
// one allowing the client credentials grant only — neither the
// authorization code grant (no redirect URI) nor CIBA — and returns the
// previous registration.
func reregisterTestClient(t *testing.T, h harness) storage.RegisteredClient {
	t.Helper()
	previous := h.clients.clients[testClientID]
	client, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID:                           testClientID,
		ClientAssertionAlgorithm:     fapi.ES256,
		AllowedScopes:                []string{"openid", "accounts", "offline_access"},
		AllowsClientCredentialsGrant: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.clients.clients[testClientID] = client
	return previous
}

func requireUnauthorizedClient(t *testing.T, err error) {
	t.Helper()
	var serverErr *server.Error
	if !errors.As(err, &serverErr) || serverErr.Code() != server.ErrorUnauthorizedClient {
		t.Fatalf("err = %v, want unauthorized_client", err)
	}
}

// TestCIBAExchangeAndRefreshRecheckTheGrantType covers a client whose
// registration no longer allows CIBA: an auth_req_id approved before
// the change is refused at the token endpoint, without being spent, and
// a refresh token from an earlier CIBA grant stops working, as an
// authorization code is refused once the client may no longer use the
// authorization code grant.
func TestCIBAExchangeAndRefreshRecheckTheGrantType(t *testing.T) {
	h, _ := newHarnessWithBackchannel(t)
	approve := func() server.BackchannelInteractionRequired {
		required := beginBackchannel(t, h, map[string]json.RawMessage{
			"scope":      jsonRaw(t, "openid accounts offline_access"),
			"login_hint": jsonRaw(t, "user-1"),
		})
		sub, _ := server.NewSubjectID("user-1")
		authSub, _ := server.NewAuthenticatedSubject(sub)
		authCtx, _ := server.NewAuthenticationContext(h.now, "", []string{"pwd"})
		if err := h.server.CompleteBackchannelAuthentication(context.Background(), server.CompleteBackchannelAuthenticationRequest{
			Handle: required.Handle,
			Result: server.Authorize(authSub, authCtx, server.GrantedAuthorization{Scope: []string{"openid", "accounts", "offline_access"}}),
		}); err != nil {
			t.Fatalf("CompleteBackchannelAuthentication: %v", err)
		}
		return required
	}
	exchange := func(required server.BackchannelInteractionRequired) (server.TokenResult, error) {
		return h.server.ExchangeBackchannelAuthentication(context.Background(), server.BackchannelTokenExchangeRequest{
			HTTP: server.FormRequest{Parameters: []server.FormParameter{
				formParam("client_assertion", h.clientAssertion(t)),
				formParam("client_assertion_type", clientassertion.AssertionType),
				formParam("grant_type", server.CIBAGrantType),
				formParam("auth_req_id", required.AuthReqID.String()),
			}},
			DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
		})
	}
	refresh := func(refreshToken string) error {
		_, err := h.server.RefreshAccessToken(context.Background(), server.RefreshTokenRequest{
			HTTP:       server.FormRequest{Parameters: refreshFormParams(h.clientAssertion(t), refreshToken, "")},
			DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
		})
		return err
	}

	earlier, err := exchange(approve())
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	pending := approve()

	original := reregisterTestClient(t, h)
	_, err = exchange(pending)
	requireUnauthorizedClient(t, err)
	requireUnauthorizedClient(t, refresh(earlier.RefreshToken.Reveal()))

	// Refused before polling: registered for CIBA again, the client
	// still gets its tokens.
	h.clients.clients[testClientID] = original
	if _, err := exchange(pending); err != nil {
		t.Fatalf("exchange once registered again: %v", err)
	}
	if err := refresh(earlier.RefreshToken.Reveal()); err != nil {
		t.Fatalf("refresh once registered again: %v", err)
	}
}

// TestRefreshRechecksTheAuthorizationCodeGrant covers a refresh token
// from an authorization code grant once the client may no longer use
// that grant (no redirect URI left).
func TestRefreshRechecksTheAuthorizationCodeGrant(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, false)
	tokens, _ := exchangeForTokensWithOfflineAccess(t, h)
	reregisterTestClient(t, h)
	_, err := h.server.RefreshAccessToken(context.Background(), server.RefreshTokenRequest{
		HTTP:       server.FormRequest{Parameters: refreshFormParams(h.clientAssertion(t), tokens.RefreshToken.Reveal(), "")},
		DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
	})
	requireUnauthorizedClient(t, err)
}

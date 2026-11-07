package server_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// fineGrainedScopes is a registration for an authorization server with
// fine-grained scopes, one per data item: n item scopes after extra,
// where requesting every item takes well over 4 KiB of scope.
func fineGrainedScopes(n int, extra ...string) []string {
	scopes := append([]string{}, extra...)
	for i := range n {
		scopes = append(scopes, fmt.Sprintf("data:item-%04d", i))
	}
	return scopes
}

// repeatedScope is value repeated, space-separated, until the scope is
// longer than n bytes.
func repeatedScope(value string, n int) string {
	return strings.Repeat(value+" ", n/(len(value)+1)+1)
}

// registerFineGrainedClient replaces the harness's testClientID with one
// registered for scopes, and for CIBA and client credentials too.
func registerFineGrainedClient(t *testing.T, h harness, scopes []string) {
	t.Helper()
	registerTestClient(t, h, func(c *storage.RegisteredClientConfig) {
		c.AllowedScopes = scopes
		c.BackchannelAuthenticationRequestAlgorithm = c.ClientAssertionAlgorithm
		c.AllowsClientCredentialsGrant = true
	})
}

func pushScope(t *testing.T, h harness, scope string) error {
	t.Helper()
	_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: plainFormParametersWith(t, h.clientAssertion(t), map[string]string{"scope": scope})},
	})
	return err
}

// TestScopeBoundFollowsTheClientsRegistration: a scope is bounded by
// the larger of 4 KiB and the client's allowed scopes joined with single
// spaces, so a client registered for many fine-grained scopes can push
// a request for all of them, while repeats can't take a scope past what
// it registered, and a client registered for few scopes keeps the 4 KiB
// bound.
func TestScopeBoundFollowsTheClientsRegistration(t *testing.T) {
	large := fineGrainedScopes(300, "openid", "offline_access")
	all := strings.Join(large, " ")
	if len(all) <= 4<<10 {
		t.Fatalf("test registration is %d bytes, want over 4 KiB", len(all))
	}
	small := []string{"openid", "accounts", "offline_access"}
	tests := []struct {
		name   string
		scopes []string
		scope  string
		ok     bool
	}{
		{"every registered scope", large, all, true},
		{"one byte over the registration", large, all + " ", false},
		{"repeats over the registration", large, repeatedScope("openid", len(all)), false},
		{"small registration at 4 KiB", small, "openid" + strings.Repeat(" ", 4<<10-len("openid")), true},
		{"small registration over 4 KiB", small, repeatedScope("openid", 4<<10), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, server.ProfileFAPISecurity, true)
			registerFineGrainedClient(t, h, tc.scopes)
			err := pushScope(t, h, tc.scope)
			if tc.ok {
				if err != nil {
					t.Fatalf("PushAuthorizationRequest(%d-byte scope): %v", len(tc.scope), err)
				}
				return
			}
			if err == nil {
				t.Fatalf("a %d-byte scope was accepted", len(tc.scope))
			}
			if code := serverErrorCode(t, err); code != server.ErrorInvalidRequest {
				t.Fatalf("error = %v, want invalid_request", code)
			}
			if !strings.Contains(err.Error(), fmt.Sprintf("scope must not be longer than %d bytes", max(4<<10, len(strings.Join(tc.scopes, " "))))) {
				t.Fatalf("error = %v, want the client's scope bound named", err)
			}
			if len(h.transactions.records) != 0 {
				t.Fatalf("stored %d pushed requests, want none", len(h.transactions.records))
			}
		})
	}
}

// TestFineGrainedScopesEndToEnd: a client registered for well over
// 4 KiB of scopes requests every one of them and completes the flow —
// push, begin, complete, code exchange and a refresh naming the whole
// scope again — with the scope intact at each step.
func TestFineGrainedScopesEndToEnd(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	scopes := fineGrainedScopes(300, "openid", "offline_access")
	all := strings.Join(scopes, " ")
	registerFineGrainedClient(t, h, scopes)

	handle := beginInteractionRequestingScope(t, h, all)
	result, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
		Handle: handle,
		Result: server.Authorize(testAuthenticatedSubject(t), testAuthenticationContext(t, h), server.GrantedAuthorization{Scope: scopes}),
	})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	redirect, ok := result.(server.AuthorizationRedirect)
	if !ok {
		t.Fatalf("result = %T, want server.AuthorizationRedirect", result)
	}
	dest := redirect.Destination().URL()
	dpopKey := generateKey(t)
	tokens, err := exchangeCode(t, h, dest.Query().Get("code"), dpopKey)
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	if tokens.Scope != all {
		t.Fatalf("token response scope is %d bytes, want the %d requested", len(tokens.Scope), len(all))
	}
	if !tokens.HasRefreshToken {
		t.Fatal("no refresh token, want one for offline_access")
	}

	refreshed, err := h.server.RefreshAccessToken(context.Background(), server.RefreshTokenRequest{
		HTTP:       server.FormRequest{Parameters: refreshFormParams(h.clientAssertion(t), tokens.RefreshToken.Reveal(), all)},
		DPoPProofs: []string{createDPoPProof(t, dpopKey, h.now)},
	})
	if err != nil {
		t.Fatalf("RefreshAccessToken: %v", err)
	}
	if refreshed.Scope != all {
		t.Fatalf("refreshed scope is %d bytes, want the %d requested", len(refreshed.Scope), len(all))
	}
}

func testAuthenticatedSubject(t *testing.T) server.AuthenticatedSubject {
	t.Helper()
	id, err := server.NewSubjectID("user-1")
	if err != nil {
		t.Fatalf("NewSubjectID: %v", err)
	}
	subject, err := server.NewAuthenticatedSubject(id)
	if err != nil {
		t.Fatalf("NewAuthenticatedSubject: %v", err)
	}
	return subject
}

func testAuthenticationContext(t *testing.T, h harness) server.AuthenticationContext {
	t.Helper()
	authCtx, err := server.NewAuthenticationContext(h.now, "acr-1", []string{"pwd"})
	if err != nil {
		t.Fatalf("NewAuthenticationContext: %v", err)
	}
	return authCtx
}

// TestRefreshScopeBound: a refresh request's scope, which may repeat
// the grant's values, is bounded the same way: past 4 KiB for a client
// registered for few scopes it's refused with invalid_request.
func TestRefreshScopeBound(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	first, dpopKey := exchangeForTokensWithOfflineAccess(t, h)
	_, err := h.server.RefreshAccessToken(context.Background(), server.RefreshTokenRequest{
		HTTP:       server.FormRequest{Parameters: refreshFormParams(h.clientAssertion(t), first.RefreshToken.Reveal(), repeatedScope("accounts", 4<<10))},
		DPoPProofs: []string{createDPoPProof(t, dpopKey, h.now)},
	})
	if code := serverErrorCode(t, err); code != server.ErrorInvalidRequest {
		t.Fatalf("error = %v, want invalid_request", err)
	}
}

func beginBackchannelScope(t *testing.T, h harness, scope string) server.BackchannelAuthenticationAction {
	t.Helper()
	params := standardBackchannelParams(t)
	params["scope"] = jsonRaw(t, scope)
	action, err := h.server.BeginBackchannelAuthentication(context.Background(), server.BeginBackchannelAuthenticationRequest{
		HTTP: server.FormRequest{Parameters: backchannelFormParams(h.clientAssertion(t), h.backchannelRequestObject(t, params))},
	})
	if err != nil {
		t.Fatalf("BeginBackchannelAuthentication: %v", err)
	}
	return action
}

// TestCIBAScopeBoundFollowsTheClientsRegistration: a backchannel
// authentication request's scope has the same bound as a pushed
// request's.
func TestCIBAScopeBoundFollowsTheClientsRegistration(t *testing.T) {
	large := fineGrainedScopes(300, "openid")
	all := strings.Join(large, " ")
	small := []string{"openid", "accounts", "offline_access"}
	tests := []struct {
		name   string
		scopes []string
		scope  string
		ok     bool
	}{
		{"every registered scope", large, all, true},
		{"one byte over the registration", large, all + " ", false},
		{"repeats over the registration", large, repeatedScope("openid", len(all)), false},
		{"small registration at 4 KiB", small, "openid" + strings.Repeat(" ", 4<<10-len("openid")), true},
		{"small registration over 4 KiB", small, repeatedScope("openid", 4<<10), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := newHarnessWithBackchannel(t)
			registerFineGrainedClient(t, h, tc.scopes)
			action := beginBackchannelScope(t, h, tc.scope)
			if tc.ok {
				if _, ok := action.(server.BackchannelInteractionRequired); !ok {
					t.Fatalf("action = %#v, want BackchannelInteractionRequired", action)
				}
				return
			}
			local, ok := action.(server.BackchannelAuthenticationLocalError)
			if !ok || local.Error.Code() != server.ErrorInvalidRequest {
				t.Fatalf("action = %#v, want an invalid_request local error", action)
			}
		})
	}
}

// TestCIBAFineGrainedScopesEndToEnd: a CIBA request for every one of
// well over 4 KiB of registered scopes is approved and polled for
// tokens with its scope intact.
func TestCIBAFineGrainedScopesEndToEnd(t *testing.T) {
	h, _ := newHarnessWithBackchannel(t)
	scopes := fineGrainedScopes(300, "openid")
	all := strings.Join(scopes, " ")
	registerFineGrainedClient(t, h, scopes)

	required, ok := beginBackchannelScope(t, h, all).(server.BackchannelInteractionRequired)
	if !ok {
		t.Fatal("BeginBackchannelAuthentication didn't require an interaction")
	}
	if err := h.server.CompleteBackchannelAuthentication(context.Background(), server.CompleteBackchannelAuthenticationRequest{
		Handle: required.Handle,
		Result: server.Authorize(testAuthenticatedSubject(t), testAuthenticationContext(t, h), server.GrantedAuthorization{Scope: scopes}),
	}); err != nil {
		t.Fatalf("CompleteBackchannelAuthentication: %v", err)
	}
	result, err := h.server.ExchangeBackchannelAuthentication(context.Background(), server.BackchannelTokenExchangeRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_assertion", h.clientAssertion(t)),
			formParam("client_assertion_type", clientassertion.AssertionType),
			formParam("grant_type", server.CIBAGrantType),
			formParam("auth_req_id", required.AuthReqID.String()),
		}},
		DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
	})
	if err != nil {
		t.Fatalf("ExchangeBackchannelAuthentication: %v", err)
	}
	if result.Scope != all {
		t.Fatalf("token response scope is %d bytes, want the %d requested", len(result.Scope), len(all))
	}
}

// TestClientCredentialsScopeBoundFollowsTheClientsRegistration: a
// client_credentials request's scope, which an opaque access token's
// record keeps as requested, has the same bound.
func TestClientCredentialsScopeBoundFollowsTheClientsRegistration(t *testing.T) {
	large := fineGrainedScopes(300)
	all := strings.Join(large, " ")
	small := []string{"accounts"}
	tests := []struct {
		name   string
		scopes []string
		scope  string
		ok     bool
	}{
		{"every registered scope", large, all, true},
		{"one byte over the registration", large, all + " ", false},
		{"repeats over the registration", large, repeatedScope("data:item-0000", len(all)), false},
		{"small registration at 4 KiB", small, "accounts" + strings.Repeat(" ", 4<<10-len("accounts")), true},
		{"small registration over 4 KiB", small, repeatedScope("accounts", 4<<10), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarnessWithClientCredentialsGrant(t, storage.SenderConstrainDPoP, true)
			registerFineGrainedClient(t, h, tc.scopes)
			result, err := h.server.RequestClientCredentialsToken(context.Background(), server.ClientCredentialsTokenRequest{
				HTTP:       server.FormRequest{Parameters: clientCredentialsFormParams(h.clientAssertion(t), tc.scope)},
				DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
			})
			if tc.ok {
				if err != nil {
					t.Fatalf("RequestClientCredentialsToken(%d-byte scope): %v", len(tc.scope), err)
				}
				if want := strings.Join(strings.Fields(tc.scope), " "); result.Scope != want {
					t.Fatalf("token response scope is %d bytes, want %d", len(result.Scope), len(want))
				}
				return
			}
			if code := serverErrorCode(t, err); code != server.ErrorInvalidRequest {
				t.Fatalf("error = %v, want invalid_request", err)
			}
		})
	}
}

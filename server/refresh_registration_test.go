package server_test

import (
	"context"
	"encoding/json"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// reregister replaces testClientID's registration in h.clients with one
// allowing only scopes (and, when set, only RAR types), as an operator
// changing a client's registration after it was issued tokens.
func reregister(t *testing.T, h harness, scopes, types []string, cibaAndRAR bool) {
	t.Helper()
	cfg := storage.RegisteredClientConfig{
		ID:                       testClientID,
		RedirectURIs:             []fapi.RegisteredRedirectURI{testRedirectURI},
		ClientAssertionAlgorithm: fapi.ES256,
		RequestObjectAlgorithm:   fapi.ES256,
		AllowedScopes:            scopes,
	}
	if cibaAndRAR {
		cfg.BackchannelAuthenticationRequestAlgorithm = fapi.ES256
		cfg.AuthorizationDetailsTypes = types
	}
	client, err := storage.NewRegisteredClient(cfg)
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}
	h.clients.clients[testClientID] = client
}

func refreshWith(t *testing.T, h harness, refreshToken, scope string) (server.TokenResult, error) {
	t.Helper()
	return h.server.RefreshAccessToken(context.Background(), server.RefreshTokenRequest{
		HTTP:       server.FormRequest{Parameters: refreshFormParams(h.clientAssertion(t), refreshToken, scope)},
		DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
	})
}

// TestRefreshRechecksClientScopes covers a scope removed from the
// client's registration after its refresh token was issued: refreshing
// the full grant is refused with invalid_scope, while a refresh that
// narrows to the scopes the client may still use succeeds.
func TestRefreshRechecksClientScopes(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	tokens, _ := exchangeForTokensWithOfflineAccess(t, h)
	reregister(t, h, []string{"openid", "offline_access"}, nil, false)

	if _, err := refreshWith(t, h, tokens.RefreshToken.Reveal(), ""); serverErrorCode(t, err) != server.ErrorInvalidScope {
		t.Fatalf("refresh of the full grant after de-scoping: %v, want invalid_scope", err)
	}
	result, err := refreshWith(t, h, tokens.RefreshToken.Reveal(), "openid offline_access")
	if err != nil {
		t.Fatalf("refresh narrowed to the still-allowed scopes: %v", err)
	}
	if result.Scope != "openid offline_access" || !result.HasIDToken {
		t.Errorf("narrowed refresh = scope %q, id token %v; want openid offline_access with an ID token", result.Scope, result.HasIDToken)
	}
}

// TestRefreshRechecksOAuthOnly covers Config.OAuthOnly turned on after a
// grant with openid was issued: no ID token is issued on refresh, and the
// full grant is refused until the client narrows away openid.
func TestRefreshRechecksOAuthOnly(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	tokens, _ := exchangeForTokensWithOfflineAccess(t, h)

	cfg := h.cfg
	cfg.OAuthOnly = true
	srv, err := server.New(cfg, h.deps)
	if err != nil {
		t.Fatalf("server.New(OAuthOnly): %v", err)
	}
	h.server = srv

	if _, err := refreshWith(t, h, tokens.RefreshToken.Reveal(), ""); serverErrorCode(t, err) != server.ErrorInvalidScope {
		t.Fatalf("refresh including openid under OAuthOnly: %v, want invalid_scope", err)
	}
	result, err := refreshWith(t, h, tokens.RefreshToken.Reveal(), "accounts offline_access")
	if err != nil {
		t.Fatalf("refresh narrowed away from openid: %v", err)
	}
	if result.HasIDToken {
		t.Error("refresh under OAuthOnly issued an ID token")
	}
}

// TestCIBAExchangeRechecksClient covers a client de-scoped, or with an
// authorization_details type deregistered, between the user's approval
// and the token request: the CIBA token exchange refuses the grant.
func TestCIBAExchangeRechecksClient(t *testing.T) {
	for name, tc := range map[string]struct {
		scopes, types []string
		want          server.ErrorCode
	}{
		"scope removed":    {[]string{"openid"}, []string{"payment"}, server.ErrorInvalidScope},
		"RAR type removed": {[]string{"openid", "accounts"}, nil, server.ErrorInvalidGrant},
	} {
		t.Run(name, func(t *testing.T) {
			policy := fakeRARPolicy{allow: map[string]bool{"payment": true}}
			h := newHarnessWithRAR(t, server.ProfileFAPISecurity, newTestRARRegistry(t), policy, policy)
			params := standardBackchannelParams(t)
			params["authorization_details"] = jsonRaw(t, []testPaymentDetail{{Type: "payment", Actions: []string{"approve"}, Amount: "SGD 500.00"}})
			required := beginBackchannel(t, h, params)
			details, err := extension.RARGet(required.Interaction.AuthorizationDetails, paymentRARDef)
			if err != nil {
				t.Fatalf("RARGet: %v", err)
			}
			subject, authCtx := rarSubjectAndAuthCtx(t, h.now)
			if err := h.server.CompleteBackchannelAuthentication(context.Background(), server.CompleteBackchannelAuthenticationRequest{
				Handle: required.Handle,
				Result: server.Authorize(subject, authCtx, server.GrantedAuthorization{
					Scope:                []string{"openid", "accounts"},
					AuthorizationDetails: []json.RawMessage{mustMarshal(t, details[0].Fields)},
				}),
			}); err != nil {
				t.Fatalf("CompleteBackchannelAuthentication: %v", err)
			}

			reregister(t, h, tc.scopes, tc.types, true)

			_, err = h.server.ExchangeBackchannelAuthentication(context.Background(), server.BackchannelTokenExchangeRequest{
				HTTP: server.FormRequest{Parameters: []server.FormParameter{
					formParam("client_assertion", h.clientAssertion(t)),
					formParam("client_assertion_type", clientassertion.AssertionType),
					formParam("grant_type", server.CIBAGrantType),
					formParam("auth_req_id", required.AuthReqID.String()),
				}},
				DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
			})
			if code := serverErrorCode(t, err); code != tc.want {
				t.Fatalf("ExchangeBackchannelAuthentication after re-registration: %v, want %s", err, tc.want)
			}
		})
	}
}

// TestEmbedderRefreshRechecksClient covers a refresh token issued with
// IssueRefreshToken: it goes through RefreshAccessToken, so deregistering
// its authorization_details type refuses the refresh with invalid_grant.
func TestEmbedderRefreshRechecksClient(t *testing.T) {
	attesterKey := generateKey(t)
	h := newEmbedderRefreshHarness(t, attesterKey)
	issuing := &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}
	attested, binding := embedderTokenRequest(t, issuing)
	refreshToken, err := h.server.IssueRefreshToken(context.Background(), server.IssueRefreshTokenRequest{
		GrantType: preAuthorizedCodeGrant, Client: attested, Binding: binding,
		Subject: mustSubjectID(t, "holder-1"), Scope: []string{"accounts"},
		AuthorizationDetails: []json.RawMessage{testPaymentDetailJSON},
	})
	if err != nil {
		t.Fatalf("IssueRefreshToken: %v", err)
	}
	if _, err := issuing.refresh(refreshToken.Reveal()); err != nil {
		t.Fatalf("refresh before deregistration: %v", err)
	}

	client, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID: testClientID, RedirectURIs: []fapi.RegisteredRedirectURI{testRedirectURI},
		ClientAuthMethod: storage.ClientAuthMethodAttestation, ExpectedAttesterIssuer: testAttesterIssuer,
		ClientAttestationAlgorithm: fapi.ES256, AllowedScopes: []string{"openid", "accounts"},
	})
	if err != nil {
		t.Fatal(err)
	}
	h.clients.clients[testClientID] = client

	if _, err := issuing.refresh(refreshToken.Reveal()); serverErrorCode(t, err) != server.ErrorInvalidGrant {
		t.Fatalf("refresh after the RAR type was deregistered: %v, want invalid_grant", err)
	}
}

// TestCIBAExchangeRechecksServerRARRegistry covers a Rich Authorization
// Request type removed from Config.RAR (or RAR switched off) between the
// user's approval and the token request: the stored details no longer
// parse, and the exchange is refused with invalid_grant.
func TestCIBAExchangeRechecksServerRARRegistry(t *testing.T) {
	otherOnly, err := extension.NewRARRegistry(4096, 4, extension.RARDefinition[testPaymentDetail]{Type: "other", MaxObjects: 5, MaxBytesPerObject: 1024})
	if err != nil {
		t.Fatal(err)
	}
	for name, registry := range map[string]*extension.RARRegistry{"type removed": otherOnly, "RAR switched off": nil} {
		t.Run(name, func(t *testing.T) {
			policy := fakeRARPolicy{allow: map[string]bool{"payment": true}}
			h := newHarnessWithRAR(t, server.ProfileFAPISecurity, newTestRARRegistry(t), policy, policy)
			params := standardBackchannelParams(t)
			params["authorization_details"] = jsonRaw(t, []testPaymentDetail{{Type: "payment", Actions: []string{"approve"}, Amount: "SGD 500.00"}})
			required := beginBackchannel(t, h, params)
			details, err := extension.RARGet(required.Interaction.AuthorizationDetails, paymentRARDef)
			if err != nil {
				t.Fatalf("RARGet: %v", err)
			}
			subject, authCtx := rarSubjectAndAuthCtx(t, h.now)
			if err := h.server.CompleteBackchannelAuthentication(context.Background(), server.CompleteBackchannelAuthenticationRequest{
				Handle: required.Handle,
				Result: server.Authorize(subject, authCtx, server.GrantedAuthorization{
					Scope:                []string{"openid", "accounts"},
					AuthorizationDetails: []json.RawMessage{mustMarshal(t, details[0].Fields)},
				}),
			}); err != nil {
				t.Fatalf("CompleteBackchannelAuthentication: %v", err)
			}

			cfg := h.cfg
			cfg.RAR = registry
			srv, err := server.New(cfg, h.deps)
			if err != nil {
				t.Fatalf("server.New: %v", err)
			}
			_, err = srv.ExchangeBackchannelAuthentication(context.Background(), server.BackchannelTokenExchangeRequest{
				HTTP: server.FormRequest{Parameters: []server.FormParameter{
					formParam("client_assertion", h.clientAssertion(t)),
					formParam("client_assertion_type", clientassertion.AssertionType),
					formParam("grant_type", server.CIBAGrantType),
					formParam("auth_req_id", required.AuthReqID.String()),
				}},
				DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
			})
			if code := serverErrorCode(t, err); code != server.ErrorInvalidGrant {
				t.Fatalf("ExchangeBackchannelAuthentication after the registry changed: %v, want invalid_grant", err)
			}
		})
	}
}

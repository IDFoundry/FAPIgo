package server_test

import (
	"context"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/server"
)

const otherTenantIssuer = "https://tenant-b.example.com"

// otherTenant is a server with its own issuer and signing key over h's
// stores and client registry: two tenants of one deployment sharing a
// database, the sharing Server.ownsRecord refuses across issuers.
func otherTenant(t *testing.T, h harness) (*server.Server, func() string) {
	t.Helper()
	cfg := h.cfg
	issuer, err := fapi.ParseIssuerURL(otherTenantIssuer)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Issuer = issuer
	deps := h.deps
	keys := &fakeKeyManager{key: generateKey(t), keyID: "tenant-b"}
	deps.Keys = keys
	deps.AccessTokens = server.JWTAccessTokens{Keys: keys, Algorithm: fapi.ES256}
	srv, err := server.New(cfg, deps)
	if err != nil {
		t.Fatalf("server.New(tenant B): %v", err)
	}
	assertion := func() string {
		a, err := clientassertion.CreateAssertion(clientassertion.AssertionRequest{
			Signer: h.key, Algorithm: fapi.ES256, ClientID: testClientID.String(), Audience: otherTenantIssuer,
			Now: h.now, Lifetime: 30 * time.Second,
		})
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	return srv, assertion
}

// TestRecordsFromAnotherIssuerAreUnknown covers two servers with
// different issuers over the same stores: neither redeems or continues
// what the other wrote — an authorization code, a refresh token, a
// request_uri or an interaction handle — answering as it would for an
// unknown one, while the server that wrote them still can.
func TestRecordsFromAnotherIssuerAreUnknown(t *testing.T) {
	ctx := context.Background()

	t.Run("authorization code", func(t *testing.T) {
		h := newHarness(t, server.ProfileFAPISecurity, true)
		tenantB, assertionB := otherTenant(t, h)
		code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts"})
		_, err := tenantB.ExchangeAuthorizationCode(ctx, server.AuthorizationCodeExchangeRequest{
			HTTP:       server.FormRequest{Parameters: exchangeFormParams(assertionB(), code, testRedirectURI, testCodeVerifier)},
			DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
		})
		if code := serverErrorCode(t, err); code != server.ErrorInvalidGrant {
			t.Fatalf("tenant B redeeming tenant A's code: error code %q, want %q", code, server.ErrorInvalidGrant)
		}
	})

	t.Run("refresh token", func(t *testing.T) {
		h := newHarness(t, server.ProfileFAPISecurity, true)
		tenantB, assertionB := otherTenant(t, h)
		code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts", "offline_access"})
		tokens, err := h.server.ExchangeAuthorizationCode(ctx, server.AuthorizationCodeExchangeRequest{
			HTTP:       server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
			DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
		})
		if err != nil || !tokens.HasRefreshToken {
			t.Fatalf("ExchangeAuthorizationCode = %v (refresh token %v)", err, tokens.HasRefreshToken)
		}
		_, err = tenantB.RefreshAccessToken(ctx, server.RefreshTokenRequest{
			HTTP:       server.FormRequest{Parameters: refreshFormParams(assertionB(), tokens.RefreshToken.Reveal(), "")},
			DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
		})
		if code := serverErrorCode(t, err); code != server.ErrorInvalidGrant {
			t.Fatalf("tenant B refreshing tenant A's refresh token: error code %q, want %q", code, server.ErrorInvalidGrant)
		}
		if _, err := h.server.RefreshAccessToken(ctx, server.RefreshTokenRequest{
			HTTP:       server.FormRequest{Parameters: refreshFormParams(h.clientAssertion(t), tokens.RefreshToken.Reveal(), "")},
			DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
		}); err != nil {
			t.Fatalf("tenant A refreshing its own refresh token: %v", err)
		}
	})

	t.Run("request_uri", func(t *testing.T) {
		h := newHarness(t, server.ProfileFAPISecurity, true)
		tenantB, _ := otherTenant(t, h)
		pushed, err := h.server.PushAuthorizationRequest(ctx, server.PushAuthorizationRequest{
			HTTP: server.FormRequest{Parameters: plainFormParameters(t, h.clientAssertion(t), nil)},
		})
		if err != nil {
			t.Fatalf("PushAuthorizationRequest: %v", err)
		}
		action, err := tenantB.BeginAuthorization(ctx, server.BeginAuthorizationRequest{
			RequestURI: pushed.RequestURI.String(), ClientID: testClientID,
		})
		if err != nil {
			t.Fatalf("BeginAuthorization: %v", err)
		}
		local, ok := action.(server.LocalErrorResponse)
		if !ok || local.Error.Code() != server.ErrorInvalidRequestURI {
			t.Fatalf("tenant B beginning tenant A's request_uri = %#v, want a local invalid_request_uri", action)
		}
	})

	t.Run("interaction handle", func(t *testing.T) {
		h := newHarness(t, server.ProfileFAPISecurity, true)
		tenantB, _ := otherTenant(t, h)
		handle := beginInteraction(t, h)
		subjectID, err := server.NewSubjectID("user-1")
		if err != nil {
			t.Fatal(err)
		}
		subject, err := server.NewAuthenticatedSubject(subjectID)
		if err != nil {
			t.Fatal(err)
		}
		authCtx, err := server.NewAuthenticationContext(h.now, "acr-1", []string{"pwd"})
		if err != nil {
			t.Fatal(err)
		}
		result, err := tenantB.CompleteAuthorization(ctx, server.CompleteAuthorizationRequest{
			Handle: handle,
			Result: server.Authorize(subject, authCtx, server.GrantedAuthorization{Scope: []string{"openid", "accounts"}}),
		})
		if err != nil {
			t.Fatalf("CompleteAuthorization: %v", err)
		}
		local, ok := result.(server.AuthorizationLocalError)
		if !ok || local.Error.Code() != server.ErrorInvalidRequest {
			t.Fatalf("tenant B completing tenant A's interaction = %#v, want a local invalid_request", result)
		}
	})
}

// TestBackchannelRecordsFromAnotherIssuerAreUnknown covers CIBA across
// two issuers over the same stores: the other server can neither look
// up nor decide tenant A's backchannel authentication, nor redeem its
// auth_req_id once approved.
func TestBackchannelRecordsFromAnotherIssuerAreUnknown(t *testing.T) {
	ctx := context.Background()
	h, _ := newHarnessWithBackchannel(t)
	tenantB, assertionB := otherTenant(t, h)
	required := beginBackchannel(t, h, standardBackchannelParams(t))

	if _, err := tenantB.LookupBackchannelInteraction(ctx, required.Handle); serverErrorCode(t, err) != server.ErrorInvalidRequest {
		t.Errorf("tenant B looking up tenant A's backchannel handle = %v, want invalid_request", err)
	}
	subjectID, err := server.NewSubjectID("user-1")
	if err != nil {
		t.Fatal(err)
	}
	subject, err := server.NewAuthenticatedSubject(subjectID)
	if err != nil {
		t.Fatal(err)
	}
	authCtx, err := server.NewAuthenticationContext(h.now, "acr-1", []string{"pwd"})
	if err != nil {
		t.Fatal(err)
	}
	if err := tenantB.CompleteBackchannelAuthentication(ctx, server.CompleteBackchannelAuthenticationRequest{
		Handle: required.Handle,
		Result: server.Authorize(subject, authCtx, server.GrantedAuthorization{Scope: []string{"openid", "accounts"}}),
	}); serverErrorCode(t, err) != server.ErrorInvalidRequest {
		t.Errorf("tenant B deciding tenant A's backchannel authentication = %v, want invalid_request", err)
	}

	poll := func(authReqID server.AuthReqID) error {
		_, err := tenantB.ExchangeBackchannelAuthentication(ctx, server.BackchannelTokenExchangeRequest{
			HTTP: server.FormRequest{Parameters: []server.FormParameter{
				formParam("client_assertion", assertionB()),
				formParam("client_assertion_type", clientassertion.AssertionType),
				formParam("grant_type", server.CIBAGrantType),
				formParam("auth_req_id", authReqID.String()),
			}},
			DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
		})
		return err
	}
	// Still pending: tenant B doesn't even say so (authorization_pending
	// would tell it the auth_req_id exists). A second request, since a
	// store throttles a repeated poll of one auth_req_id (slow_down).
	pending := beginBackchannel(t, h, standardBackchannelParams(t))
	if code := serverErrorCode(t, poll(pending.AuthReqID)); code != server.ErrorInvalidGrant {
		t.Errorf("tenant B polling tenant A's pending auth_req_id: error code %q, want %q", code, server.ErrorInvalidGrant)
	}
	approveBackchannel(t, h, required.Handle)
	if code := serverErrorCode(t, poll(required.AuthReqID)); code != server.ErrorInvalidGrant {
		t.Fatalf("tenant B redeeming tenant A's approved auth_req_id: error code %q, want %q", code, server.ErrorInvalidGrant)
	}
}

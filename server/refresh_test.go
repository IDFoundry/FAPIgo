package server_test

import (
	"context"
	"crypto/ecdsa"
	"testing"

	"github.com/osanderson/go-fapi/server"
)

func refreshFormParams(assertion, refreshToken, scope string) []server.FormParameter {
	params := []server.FormParameter{
		formParam("client_assertion", assertion),
		formParam("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
		formParam("grant_type", "refresh_token"),
		formParam("refresh_token", refreshToken),
	}
	if scope != "" {
		params = append(params, formParam("scope", scope))
	}
	return params
}

// exchangeForTokensWithOfflineAccess runs the full push/begin/complete/
// exchange flow granting "openid accounts offline_access" and returns the
// resulting TokenResult and the DPoP key used at exchange time.
func exchangeForTokensWithOfflineAccess(t *testing.T, h harness) (server.TokenResult, *ecdsa.PrivateKey) {
	t.Helper()
	code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts", "offline_access"})
	dpopKey := generateKey(t)
	result, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:      server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
		DPoPProof: createDPoPProof(t, dpopKey, h.now),
	})
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	if !result.HasRefreshToken || result.RefreshToken.Reveal() == "" {
		t.Fatalf("expected a refresh token since scope included offline_access")
	}
	return result, dpopKey
}

func TestExchangeAuthorizationCodeIssuesRefreshTokenForOfflineAccess(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	exchangeForTokensWithOfflineAccess(t, h)
}

func TestExchangeAuthorizationCodeNoRefreshTokenWithoutOfflineAccess(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts"})

	result, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:      server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
		DPoPProof: createDPoPProof(t, generateKey(t), h.now),
	})
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	if result.HasRefreshToken {
		t.Fatalf("HasRefreshToken = true, want false")
	}
}

func TestRefreshAccessTokenSuccess(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	first, dpopKey := exchangeForTokensWithOfflineAccess(t, h)

	result, err := h.server.RefreshAccessToken(context.Background(), server.RefreshTokenRequest{
		HTTP:      server.FormRequest{Parameters: refreshFormParams(h.clientAssertion(t), first.RefreshToken.Reveal(), "")},
		DPoPProof: createDPoPProof(t, dpopKey, h.now),
	})
	if err != nil {
		t.Fatalf("RefreshAccessToken: %v", err)
	}
	if result.AccessToken.Reveal() == "" {
		t.Fatalf("AccessToken is empty")
	}
	if result.AccessToken.Reveal() == first.AccessToken.Reveal() {
		t.Fatalf("refreshed access token equals the original")
	}
	if result.Scope != "openid accounts offline_access" {
		t.Fatalf("Scope = %q, want %q", result.Scope, "openid accounts offline_access")
	}
	if !result.HasIDToken || result.IDToken.Reveal() == "" {
		t.Fatalf("expected an ID token since scope included openid")
	}
	if !result.HasRefreshToken || result.RefreshToken.Reveal() == "" {
		t.Fatalf("expected a rotated refresh token")
	}
	if result.RefreshToken.Reveal() == first.RefreshToken.Reveal() {
		t.Fatalf("refresh token was not rotated")
	}
}

func TestRefreshAccessTokenOldTokenIsSingleUse(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	first, dpopKey := exchangeForTokensWithOfflineAccess(t, h)

	if _, err := h.server.RefreshAccessToken(context.Background(), server.RefreshTokenRequest{
		HTTP:      server.FormRequest{Parameters: refreshFormParams(h.clientAssertion(t), first.RefreshToken.Reveal(), "")},
		DPoPProof: createDPoPProof(t, dpopKey, h.now),
	}); err != nil {
		t.Fatalf("first RefreshAccessToken: %v", err)
	}

	_, err := h.server.RefreshAccessToken(context.Background(), server.RefreshTokenRequest{
		HTTP:      server.FormRequest{Parameters: refreshFormParams(h.clientAssertion(t), first.RefreshToken.Reveal(), "")},
		DPoPProof: createDPoPProof(t, dpopKey, h.now),
	})
	if err == nil {
		t.Fatalf("second RefreshAccessToken (replayed token) = nil error, want error")
	}
	if code := serverErrorCode(t, err); code != server.ErrorInvalidGrant {
		t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidGrant)
	}
}

func TestRefreshAccessTokenNarrowsScope(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	first, dpopKey := exchangeForTokensWithOfflineAccess(t, h)

	result, err := h.server.RefreshAccessToken(context.Background(), server.RefreshTokenRequest{
		HTTP:      server.FormRequest{Parameters: refreshFormParams(h.clientAssertion(t), first.RefreshToken.Reveal(), "accounts")},
		DPoPProof: createDPoPProof(t, dpopKey, h.now),
	})
	if err != nil {
		t.Fatalf("RefreshAccessToken: %v", err)
	}
	if result.Scope != "accounts" {
		t.Fatalf("Scope = %q, want %q", result.Scope, "accounts")
	}
	if result.HasIDToken {
		t.Fatalf("HasIDToken = true, want false (narrowed scope excluded openid)")
	}
}

func TestRefreshAccessTokenRejectsWideningScope(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	first, dpopKey := exchangeForTokensWithOfflineAccess(t, h)

	_, err := h.server.RefreshAccessToken(context.Background(), server.RefreshTokenRequest{
		HTTP:      server.FormRequest{Parameters: refreshFormParams(h.clientAssertion(t), first.RefreshToken.Reveal(), "openid accounts offline_access payments")},
		DPoPProof: createDPoPProof(t, dpopKey, h.now),
	})
	if err == nil {
		t.Fatalf("RefreshAccessToken(widened scope) = nil error, want error")
	}
	if code := serverErrorCode(t, err); code != server.ErrorInvalidScope {
		t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidScope)
	}
}

func TestRefreshAccessTokenRejectsWrongDPoPKey(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	first, _ := exchangeForTokensWithOfflineAccess(t, h)

	wrongKey := generateKey(t)
	_, err := h.server.RefreshAccessToken(context.Background(), server.RefreshTokenRequest{
		HTTP:      server.FormRequest{Parameters: refreshFormParams(h.clientAssertion(t), first.RefreshToken.Reveal(), "")},
		DPoPProof: createDPoPProof(t, wrongKey, h.now),
	})
	if err == nil {
		t.Fatalf("RefreshAccessToken(wrong DPoP key) = nil error, want error")
	}
	if code := serverErrorCode(t, err); code != server.ErrorInvalidGrant {
		t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidGrant)
	}
}

func TestRefreshAccessTokenRequiresDPoP(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	first, _ := exchangeForTokensWithOfflineAccess(t, h)

	_, err := h.server.RefreshAccessToken(context.Background(), server.RefreshTokenRequest{
		HTTP: server.FormRequest{Parameters: refreshFormParams(h.clientAssertion(t), first.RefreshToken.Reveal(), "")},
	})
	if err == nil {
		t.Fatalf("RefreshAccessToken(no DPoP) = nil error, want error")
	}
	if code := serverErrorCode(t, err); code != server.ErrorInvalidRequest {
		t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidRequest)
	}
}

func TestRefreshAccessTokenRejectsWrongGrantType(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	first, dpopKey := exchangeForTokensWithOfflineAccess(t, h)

	params := refreshFormParams(h.clientAssertion(t), first.RefreshToken.Reveal(), "")
	for i := range params {
		if params[i].Name == "grant_type" {
			params[i].Value = "authorization_code"
		}
	}
	_, err := h.server.RefreshAccessToken(context.Background(), server.RefreshTokenRequest{
		HTTP: server.FormRequest{Parameters: params}, DPoPProof: createDPoPProof(t, dpopKey, h.now),
	})
	if code := serverErrorCode(t, err); code != server.ErrorUnsupportedGrantType {
		t.Fatalf("error code = %q, want %q", code, server.ErrorUnsupportedGrantType)
	}
}

func TestRefreshAccessTokenRejectsMissingClientAssertion(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	first, dpopKey := exchangeForTokensWithOfflineAccess(t, h)

	params := refreshFormParams("", first.RefreshToken.Reveal(), "")
	filtered := params[:0]
	for _, p := range params {
		if p.Name != "client_assertion" {
			filtered = append(filtered, p)
		}
	}
	_, err := h.server.RefreshAccessToken(context.Background(), server.RefreshTokenRequest{
		HTTP: server.FormRequest{Parameters: filtered}, DPoPProof: createDPoPProof(t, dpopKey, h.now),
	})
	if code := serverErrorCode(t, err); code != server.ErrorInvalidClient {
		t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidClient)
	}
}

func TestRefreshAccessTokenAuditsOutcomes(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	first, dpopKey := exchangeForTokensWithOfflineAccess(t, h)

	if _, err := h.server.RefreshAccessToken(context.Background(), server.RefreshTokenRequest{
		HTTP:      server.FormRequest{Parameters: refreshFormParams(h.clientAssertion(t), first.RefreshToken.Reveal(), "")},
		DPoPProof: createDPoPProof(t, dpopKey, h.now),
	}); err != nil {
		t.Fatalf("RefreshAccessToken: %v", err)
	}

	var success int
	for _, e := range h.audit.all() {
		if e.Type == server.AuditEventRefreshAccessToken && e.Outcome == server.AuditOutcomeSuccess {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("success audit events = %d, want 1", success)
	}
}

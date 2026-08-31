package server_test

import (
	"context"
	"crypto/ecdsa"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/token"
	"github.com/idfoundry/fapigo/server"
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
		HTTP:       server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
		DPoPProofs: []string{createDPoPProof(t, dpopKey, h.now)},
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
		HTTP:       server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
		DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
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
		HTTP:       server.FormRequest{Parameters: refreshFormParams(h.clientAssertion(t), first.RefreshToken.Reveal(), "")},
		DPoPProofs: []string{createDPoPProof(t, dpopKey, h.now)},
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
	// FAPI2-SP-FINAL 5.3.2.1-9: "shall not use refresh token rotation
	// except in extraordinary circumstances" — the response must echo
	// back the same refresh token, not mint a new one.
	if !result.HasRefreshToken || result.RefreshToken.Reveal() == "" {
		t.Fatalf("expected a refresh token in the response")
	}
	if result.RefreshToken.Reveal() != first.RefreshToken.Reveal() {
		t.Fatalf("refresh token was rotated; FAPI2-SP-FINAL 5.3.2.1-9 says it should not be")
	}
}

// FAPI2-SP-FINAL 5.3.2.1-9 requires refresh tokens not be rotated by
// default, which means — unlike an authorization code — the same
// refresh token must keep working across repeated use, not just once.
func TestRefreshAccessTokenReusableAcrossMultipleCalls(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	first, dpopKey := exchangeForTokensWithOfflineAccess(t, h)

	if _, err := h.server.RefreshAccessToken(context.Background(), server.RefreshTokenRequest{
		HTTP:       server.FormRequest{Parameters: refreshFormParams(h.clientAssertion(t), first.RefreshToken.Reveal(), "")},
		DPoPProofs: []string{createDPoPProof(t, dpopKey, h.now)},
	}); err != nil {
		t.Fatalf("first RefreshAccessToken: %v", err)
	}

	if _, err := h.server.RefreshAccessToken(context.Background(), server.RefreshTokenRequest{
		HTTP:       server.FormRequest{Parameters: refreshFormParams(h.clientAssertion(t), first.RefreshToken.Reveal(), "")},
		DPoPProofs: []string{createDPoPProof(t, dpopKey, h.now)},
	}); err != nil {
		t.Fatalf("second RefreshAccessToken (same token again): %v, want success", err)
	}
}

func TestRefreshAccessTokenNarrowsScope(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	first, dpopKey := exchangeForTokensWithOfflineAccess(t, h)

	result, err := h.server.RefreshAccessToken(context.Background(), server.RefreshTokenRequest{
		HTTP:       server.FormRequest{Parameters: refreshFormParams(h.clientAssertion(t), first.RefreshToken.Reveal(), "accounts")},
		DPoPProofs: []string{createDPoPProof(t, dpopKey, h.now)},
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
		HTTP:       server.FormRequest{Parameters: refreshFormParams(h.clientAssertion(t), first.RefreshToken.Reveal(), "openid accounts offline_access payments")},
		DPoPProofs: []string{createDPoPProof(t, dpopKey, h.now)},
	})
	if err == nil {
		t.Fatalf("RefreshAccessToken(widened scope) = nil error, want error")
	}
	if code := serverErrorCode(t, err); code != server.ErrorInvalidScope {
		t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidScope)
	}
}

// FAPI2SPFinal's refresh-token conformance module deliberately presents
// a brand-new DPoP key at refresh time "to check the server handles
// that correctly" (the suite's own RefreshTokenRequestSteps.java
// comment) — and RFC 9449 §5 confirms a confidential client's refresh
// token isn't bound to a specific DPoP key at all ("already
// sender-constrained with a different existing mechanism" — client
// authentication). Every client this server accepts is confidential
// (authenticateClient always requires client_assertion; there is no
// public-client path), so a rotated DPoP key at refresh time must
// succeed, and the newly issued access token must be bound to the new
// key, not the original one.
func TestRefreshAccessTokenAcceptsRotatedDPoPKey(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	first, _ := exchangeForTokensWithOfflineAccess(t, h)

	rotatedKey := generateKey(t)
	result, err := h.server.RefreshAccessToken(context.Background(), server.RefreshTokenRequest{
		HTTP:       server.FormRequest{Parameters: refreshFormParams(h.clientAssertion(t), first.RefreshToken.Reveal(), "")},
		DPoPProofs: []string{createDPoPProof(t, rotatedKey, h.now)},
	})
	if err != nil {
		t.Fatalf("RefreshAccessToken(rotated DPoP key): %v", err)
	}

	rotatedThumbprint, err := jwkThumbprintFor(rotatedKey)
	if err != nil {
		t.Fatalf("jwkThumbprintFor: %v", err)
	}
	rotatedThumbprintStr := rotatedThumbprint.String()
	parsed, err := token.ParseAccessToken(result.AccessToken.Reveal())
	if err != nil {
		t.Fatalf("ParseAccessToken: %v", err)
	}
	validated, err := parsed.Validate(&h.serverKey.PublicKey, token.AccessTokenValidatePolicy{
		ExpectedIssuer: testIssuer, ExpectedAudience: testIssuer, Algorithm: fapi.ES256,
		Now: h.now, MaxLifetime: 5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Validate refreshed access token: %v", err)
	}
	if validated.JKT != rotatedThumbprintStr {
		t.Fatalf("refreshed access token JKT = %q, want %q (not bound to the rotated DPoP key)", validated.JKT, rotatedThumbprintStr)
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
		HTTP: server.FormRequest{Parameters: params}, DPoPProofs: []string{createDPoPProof(t, dpopKey, h.now)},
	})
	if code := serverErrorCode(t, err); code != server.ErrorUnsupportedGrantType {
		t.Fatalf("error code = %q, want %q", code, server.ErrorUnsupportedGrantType)
	}
}

// TestRefreshAccessTokenRejectsMultipleDPoPProofs mirrors
// TestExchangeAuthorizationCodeRejectsMultipleDPoPProofs (see its own
// doc comment) for this grant.
func TestRefreshAccessTokenRejectsMultipleDPoPProofs(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	first, dpopKey := exchangeForTokensWithOfflineAccess(t, h)

	_, err := h.server.RefreshAccessToken(context.Background(), server.RefreshTokenRequest{
		HTTP:       server.FormRequest{Parameters: refreshFormParams(h.clientAssertion(t), first.RefreshToken.Reveal(), "")},
		DPoPProofs: []string{createDPoPProof(t, dpopKey, h.now), createDPoPProof(t, dpopKey, h.now)},
	})
	if code := serverErrorCode(t, err); code != server.ErrorInvalidRequest {
		t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidRequest)
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
		HTTP: server.FormRequest{Parameters: filtered}, DPoPProofs: []string{createDPoPProof(t, dpopKey, h.now)},
	})
	if code := serverErrorCode(t, err); code != server.ErrorInvalidClient {
		t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidClient)
	}
}

func TestRefreshAccessTokenAuditsOutcomes(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	first, dpopKey := exchangeForTokensWithOfflineAccess(t, h)

	if _, err := h.server.RefreshAccessToken(context.Background(), server.RefreshTokenRequest{
		HTTP:       server.FormRequest{Parameters: refreshFormParams(h.clientAssertion(t), first.RefreshToken.Reveal(), "")},
		DPoPProofs: []string{createDPoPProof(t, dpopKey, h.now)},
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

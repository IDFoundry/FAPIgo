package server_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/internal/token"
	"github.com/idfoundry/fapigo/server"
)

// testGrantedIDTokenClaims stands in for provider-specific claims an
// application adds at login: a claim describing the subject, and one
// describing who is acting on its behalf.
var testGrantedIDTokenClaims = map[string]json.RawMessage{
	"sub_type": json.RawMessage(`"user"`),
	"act":      json.RawMessage(`{"sub":"delegate-1"}`),
}

func authorizeWithIDTokenClaims(t *testing.T, now time.Time, scope []string, claims map[string]json.RawMessage) server.InteractionResult {
	t.Helper()
	subjectID, err := server.NewSubjectID("user-1")
	if err != nil {
		t.Fatalf("NewSubjectID: %v", err)
	}
	subject, err := server.NewAuthenticatedSubject(subjectID)
	if err != nil {
		t.Fatalf("NewAuthenticatedSubject: %v", err)
	}
	authCtx, err := server.NewAuthenticationContext(now, "urn:mace:incommon:iap:silver", []string{"pwd"})
	if err != nil {
		t.Fatalf("NewAuthenticationContext: %v", err)
	}
	return server.Authorize(subject, authCtx, server.GrantedAuthorization{Scope: scope, IDTokenClaims: claims})
}

func validateIDToken(t *testing.T, h harness, raw, accessToken string) token.ValidatedIDToken {
	t.Helper()
	parsed, err := token.ParseIDToken(raw)
	if err != nil {
		t.Fatalf("ParseIDToken: %v", err)
	}
	validated, err := parsed.Validate(&h.serverKey.PublicKey, token.IDTokenValidatePolicy{
		ExpectedIssuer: testIssuer, ExpectedAudience: testClientID.String(),
		Algorithm: fapi.ES256, Now: h.now,
		MaxLifetime: 5 * time.Minute, MaxClockSkew: 5 * time.Second,
		AccessToken: accessToken,
	})
	if err != nil {
		t.Fatalf("Validate ID token: %v", err)
	}
	return validated
}

func assertHasGrantedIDTokenClaims(t *testing.T, params map[string]json.RawMessage) {
	t.Helper()
	for name, want := range testGrantedIDTokenClaims {
		got, ok := params[name]
		if !ok {
			t.Fatalf("ID token is missing claim %q; got %v", name, params)
		}
		var gotValue, wantValue any
		if err := json.Unmarshal(got, &gotValue); err != nil {
			t.Fatalf("unmarshal %q: %v", name, err)
		}
		if err := json.Unmarshal(want, &wantValue); err != nil {
			t.Fatalf("unmarshal want %q: %v", name, err)
		}
		gotJSON, _ := json.Marshal(gotValue)
		wantJSON, _ := json.Marshal(wantValue)
		if string(gotJSON) != string(wantJSON) {
			t.Fatalf("ID token claim %q = %s, want %s", name, got, want)
		}
	}
}

func assertAccessTokenLacksGrantedIDTokenClaims(t *testing.T, h harness, accessToken string) {
	t.Helper()
	parsed, err := token.ParseAccessToken(accessToken)
	if err != nil {
		t.Fatalf("ParseAccessToken: %v", err)
	}
	validated, err := parsed.Validate(&h.serverKey.PublicKey, token.AccessTokenValidatePolicy{
		ExpectedIssuer: testIssuer, ExpectedAudience: testIssuer,
		Algorithm: fapi.ES256, Now: h.now, MaxLifetime: 10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Validate access token: %v", err)
	}
	for name := range testGrantedIDTokenClaims {
		if _, ok := validated.Parameters[name]; ok {
			t.Fatalf("access token carries ID-token-only claim %q", name)
		}
	}
}

func TestGrantedIDTokenClaimsIssuedInIDTokenOnlyAndSurviveRefresh(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	handle := beginInteractionRequestingScope(t, h, "openid accounts offline_access")
	scope := []string{"openid", "accounts", "offline_access"}

	result, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
		Handle: handle, Result: authorizeWithIDTokenClaims(t, h.now, scope, testGrantedIDTokenClaims),
	})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	redirect, ok := result.(server.AuthorizationRedirect)
	if !ok {
		t.Fatalf("result = %T, want server.AuthorizationRedirect", result)
	}
	dest := redirect.Destination().URL()
	code := dest.Query().Get("code")

	dpopKey := generateKey(t)
	exchanged, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:       server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
		DPoPProofs: []string{createDPoPProof(t, dpopKey, h.now)},
	})
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	if !exchanged.HasIDToken || !exchanged.HasRefreshToken {
		t.Fatalf("HasIDToken=%v HasRefreshToken=%v, want both", exchanged.HasIDToken, exchanged.HasRefreshToken)
	}
	assertHasGrantedIDTokenClaims(t, validateIDToken(t, h, exchanged.IDToken.Reveal(), exchanged.AccessToken.Reveal()).Parameters)
	assertAccessTokenLacksGrantedIDTokenClaims(t, h, exchanged.AccessToken.Reveal())

	refreshed, err := h.server.RefreshAccessToken(context.Background(), server.RefreshTokenRequest{
		HTTP:       server.FormRequest{Parameters: refreshFormParams(h.clientAssertion(t), exchanged.RefreshToken.Reveal(), "")},
		DPoPProofs: []string{createDPoPProof(t, dpopKey, h.now)},
	})
	if err != nil {
		t.Fatalf("RefreshAccessToken: %v", err)
	}
	if !refreshed.HasIDToken {
		t.Fatalf("refresh issued no ID token")
	}
	assertHasGrantedIDTokenClaims(t, validateIDToken(t, h, refreshed.IDToken.Reveal(), refreshed.AccessToken.Reveal()).Parameters)
	assertAccessTokenLacksGrantedIDTokenClaims(t, h, refreshed.AccessToken.Reveal())
}

func invalidGrantedIDTokenClaims() map[string]map[string]json.RawMessage {
	return map[string]map[string]json.RawMessage{
		"iss":                {"iss": json.RawMessage(`"https://evil.example"`)},
		"sub":                {"sub": json.RawMessage(`"someone-else"`)},
		"nonce":              {"nonce": json.RawMessage(`"n"`)},
		"at_hash":            {"at_hash": json.RawMessage(`"h"`)},
		"azp":                {"azp": json.RawMessage(`"other-client"`)},
		"jti":                {"jti": json.RawMessage(`"j"`)},
		"empty name":         {"": json.RawMessage(`"x"`)},
		"invalid UTF-8 name": {"name\xff": json.RawMessage(`"x"`)},
		// newHarness sets Limits.MaxIDTokenClaimsBytes to 4096.
		"over size budget": {"sub_attributes": json.RawMessage(`"` + strings.Repeat("x", 4096) + `"`)},
		"invalid JSON":     {"sub_type": json.RawMessage(`user`)},
	}
}

func TestCompleteAuthorizationRejectsInvalidGrantedIDTokenClaims(t *testing.T) {
	for name, claims := range invalidGrantedIDTokenClaims() {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, server.ProfileFAPISecurity, true)
			handle := beginInteraction(t, h)

			result, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
				Handle: handle, Result: authorizeWithIDTokenClaims(t, h.now, []string{"openid", "accounts"}, claims),
			})
			if err != nil {
				t.Fatalf("CompleteAuthorization: %v", err)
			}
			local, ok := result.(server.AuthorizationLocalError)
			if !ok {
				t.Fatalf("result = %T, want server.AuthorizationLocalError", result)
			}
			if local.Error.Code() != server.ErrorInvalidRequest {
				t.Fatalf("error code = %q, want %q", local.Error.Code(), server.ErrorInvalidRequest)
			}
			if n := len(h.grants.all()); n != 0 {
				t.Fatalf("len(codes) = %d, want 0", n)
			}
		})
	}
}

func completeBackchannelWithIDTokenClaims(t *testing.T, h harness, claims map[string]json.RawMessage) (server.BackchannelInteractionRequired, error) {
	t.Helper()
	required := beginBackchannel(t, h, standardBackchannelParams(t))
	err := h.server.CompleteBackchannelAuthentication(context.Background(), server.CompleteBackchannelAuthenticationRequest{
		Handle: required.Handle,
		Result: authorizeWithIDTokenClaims(t, h.now, []string{"openid", "accounts"}, claims),
	})
	return required, err
}

func TestCIBAGrantedIDTokenClaimsIssuedInIDTokenOnly(t *testing.T) {
	h, _ := newHarnessWithBackchannel(t)
	required, err := completeBackchannelWithIDTokenClaims(t, h, testGrantedIDTokenClaims)
	if err != nil {
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
	if !result.HasIDToken {
		t.Fatalf("HasIDToken = false, want true")
	}
	assertHasGrantedIDTokenClaims(t, validateIDToken(t, h, result.IDToken.Reveal(), result.AccessToken.Reveal()).Parameters)
	assertAccessTokenLacksGrantedIDTokenClaims(t, h, result.AccessToken.Reveal())
}

func TestCompleteBackchannelAuthenticationRejectsInvalidGrantedIDTokenClaims(t *testing.T) {
	for name, claims := range invalidGrantedIDTokenClaims() {
		t.Run(name, func(t *testing.T) {
			h, _ := newHarnessWithBackchannel(t)
			_, err := completeBackchannelWithIDTokenClaims(t, h, claims)
			if err == nil {
				t.Fatalf("CompleteBackchannelAuthentication = nil error, want error")
			}
			if code := serverErrorCode(t, err); code != server.ErrorInvalidRequest {
				t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidRequest)
			}
		})
	}
}

// TestExchangeAuthorizationCodeRejectsIDTokenClaimsOverBudget covers the
// issuance-time half of Limits.MaxIDTokenClaimsBytes: identity claims
// are only resolved at the token endpoint, so a claim set that only
// exceeds the budget once they're merged in fails there, as
// server_error, rather than issuing an ID token relying parties reject.
func TestExchangeAuthorizationCodeRejectsIDTokenClaimsOverBudget(t *testing.T) {
	identityClaims := fakeIdentityClaims{
		subject: "user-1",
		claims:  map[string]json.RawMessage{"name": json.RawMessage(`"` + strings.Repeat("n", 4096) + `"`)},
	}
	h := newHarnessWithIdentityClaims(t, identityClaims)
	code := completeAuthorizationWithClaims(t, h, `{"id_token":{"name":null}}`)

	_, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:       server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
		DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
	})
	if code := serverErrorCode(t, err); code != server.ErrorServerError {
		t.Fatalf("error code = %q, want %q", code, server.ErrorServerError)
	}
}

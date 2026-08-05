package server_test

import (
	"context"
	"crypto/ecdsa"
	"net/url"
	"testing"
	"time"

	fapi "github.com/osanderson/go-fapi"
	"github.com/osanderson/go-fapi/internal/clientassertion"
	"github.com/osanderson/go-fapi/internal/dpop"
	"github.com/osanderson/go-fapi/internal/jose"
	"github.com/osanderson/go-fapi/internal/token"
	"github.com/osanderson/go-fapi/server"
)

func jwkThumbprintFor(key *ecdsa.PrivateKey) (jose.Thumbprint, error) {
	jwk, err := jose.NewJWK(&key.PublicKey, fapi.ES256)
	if err != nil {
		return jose.Thumbprint{}, err
	}
	return jwk.Thumbprint()
}

// testCodeVerifier is the RFC 7636 Appendix B worked example, matching
// the code_challenge baked into standardAuthParams/plainFormParameters.
const testCodeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

func createDPoPProof(t *testing.T, key *ecdsa.PrivateKey, now time.Time) string {
	t.Helper()
	tokenURL, err := url.Parse(testTokenEndpoint)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	proof, err := dpop.CreateProof(dpop.ProofRequest{
		Signer: key, Algorithm: fapi.ES256, Method: "POST", URL: tokenURL, Now: now,
	})
	if err != nil {
		t.Fatalf("dpop.CreateProof: %v", err)
	}
	return proof
}

func exchangeFormParams(assertion, code, redirectURI, verifier string) []server.FormParameter {
	return []server.FormParameter{
		formParam("client_assertion", assertion),
		formParam("client_assertion_type", clientassertion.AssertionType),
		formParam("grant_type", "authorization_code"),
		formParam("code", code),
		formParam("redirect_uri", redirectURI),
		formParam("code_verifier", verifier),
	}
}

// completeSuccessfulAuthorization runs push -> begin -> complete(Authorize)
// with the given granted scope and returns the resulting authorization
// code.
// beginInteractionRequestingScope pushes and begins an authorization
// request for scope (space-delimited), so tests can grant a scope (e.g.
// "offline_access") that plainFormParameters' fixed "openid accounts"
// wouldn't have requested.
func beginInteractionRequestingScope(t *testing.T, h harness, scope string) server.InteractionHandle {
	t.Helper()
	params := []server.FormParameter{
		formParam("client_assertion", h.clientAssertion(t)),
		formParam("client_assertion_type", clientassertion.AssertionType),
		formParam("response_type", "code"),
		formParam("redirect_uri", testRedirectURI),
		formParam("scope", scope),
		formParam("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
		formParam("code_challenge_method", "S256"),
		formParam("state", "opaque-state"),
	}
	pushResult, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: params},
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
	return required.Handle
}

func completeSuccessfulAuthorization(t *testing.T, h harness, grantedScope []string) string {
	t.Helper()
	// Request a superset of anything the caller might grant, so the
	// granted-scope-subset-of-requested check in CompleteAuthorization
	// never gets in the way of what this helper is actually testing.
	handle := beginInteractionRequestingScope(t, h, "openid accounts offline_access")

	subjectID, err := server.NewSubjectID("user-1")
	if err != nil {
		t.Fatalf("NewSubjectID: %v", err)
	}
	subject, err := server.NewAuthenticatedSubject(subjectID)
	if err != nil {
		t.Fatalf("NewAuthenticatedSubject: %v", err)
	}
	authCtx, err := server.NewAuthenticationContext(h.now, "urn:mace:incommon:iap:silver", []string{"pwd"})
	if err != nil {
		t.Fatalf("NewAuthenticationContext: %v", err)
	}

	result, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
		Handle: handle,
		Result: server.Authorize(subject, authCtx, server.GrantedAuthorization{Scope: grantedScope}),
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
	if code == "" {
		t.Fatalf("redirect missing code parameter: %q", dest.String())
	}
	return code
}

func TestExchangeAuthorizationCodeSuccess(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts"})
	dpopKey := generateKey(t)

	result, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:      server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
		DPoPProof: createDPoPProof(t, dpopKey, h.now),
	})
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	if result.AccessToken.Reveal() == "" {
		t.Fatalf("AccessToken is empty")
	}
	if result.TokenType != "DPoP" {
		t.Fatalf("TokenType = %q, want %q", result.TokenType, "DPoP")
	}
	if result.ExpiresIn != 5*time.Minute {
		t.Fatalf("ExpiresIn = %v, want 5m", result.ExpiresIn)
	}
	if result.Scope != "openid accounts" {
		t.Fatalf("Scope = %q, want %q", result.Scope, "openid accounts")
	}
	if !result.HasIDToken || result.IDToken.Reveal() == "" {
		t.Fatalf("expected an ID token since scope included openid")
	}

	// Validate the access token is well-formed and DPoP-bound.
	parsedAT, err := token.ParseAccessToken(result.AccessToken.Reveal())
	if err != nil {
		t.Fatalf("ParseAccessToken: %v", err)
	}
	dpopJWK, err := jwkThumbprintFor(dpopKey)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	validatedAT, err := parsedAT.Validate(&h.serverKey.PublicKey, token.AccessTokenValidatePolicy{
		ExpectedIssuer: testIssuer, ExpectedAudience: testIssuer,
		Algorithm: fapi.ES256, ExpectedThumbprint: &dpopJWK,
		Now: h.now, MaxLifetime: 10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Validate access token: %v", err)
	}
	if validatedAT.Subject != "user-1" {
		t.Fatalf("access token Subject = %q, want %q", validatedAT.Subject, "user-1")
	}
	if validatedAT.ClientID != testClientID.String() {
		t.Fatalf("access token ClientID = %q, want %q", validatedAT.ClientID, testClientID)
	}

	// Validate the ID token.
	parsedIDT, err := token.ParseIDToken(result.IDToken.Reveal())
	if err != nil {
		t.Fatalf("ParseIDToken: %v", err)
	}
	validatedIDT, err := parsedIDT.Validate(&h.serverKey.PublicKey, token.IDTokenValidatePolicy{
		ExpectedIssuer: testIssuer, ExpectedAudience: testClientID.String(),
		Algorithm: fapi.ES256, Now: h.now, MaxLifetime: 10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Validate ID token: %v", err)
	}
	if validatedIDT.Subject != "user-1" {
		t.Fatalf("id token Subject = %q, want %q", validatedIDT.Subject, "user-1")
	}
	if validatedIDT.ACR != "urn:mace:incommon:iap:silver" {
		t.Fatalf("id token ACR = %q, want %q", validatedIDT.ACR, "urn:mace:incommon:iap:silver")
	}
}

func TestExchangeAuthorizationCodeWithoutOpenIDScope(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	code := completeSuccessfulAuthorization(t, h, []string{"accounts"})

	result, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:      server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
		DPoPProof: createDPoPProof(t, generateKey(t), h.now),
	})
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	if result.HasIDToken {
		t.Fatalf("HasIDToken = true, want false")
	}
	if result.IDToken.Reveal() != "" {
		t.Fatalf("IDToken = %q, want empty", result.IDToken.Reveal())
	}
}

func TestExchangeAuthorizationCodeRequiresDPoP(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts"})

	_, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP: server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
	})
	if err == nil {
		t.Fatalf("ExchangeAuthorizationCode(no DPoP) = nil error, want error")
	}
	if code := serverErrorCode(t, err); code != server.ErrorInvalidRequest {
		t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidRequest)
	}
}

func TestExchangeAuthorizationCodeRejectsWrongGrantType(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts"})

	params := exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)
	for i := range params {
		if params[i].Name == "grant_type" {
			params[i].Value = "client_credentials"
		}
	}
	_, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP: server.FormRequest{Parameters: params}, DPoPProof: createDPoPProof(t, generateKey(t), h.now),
	})
	if code := serverErrorCode(t, err); code != server.ErrorUnsupportedGrantType {
		t.Fatalf("error code = %q, want %q", code, server.ErrorUnsupportedGrantType)
	}
}

func TestExchangeAuthorizationCodeRejectsMissingClientAssertion(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts"})

	params := exchangeFormParams("", code, testRedirectURI, testCodeVerifier)
	filtered := params[:0]
	for _, p := range params {
		if p.Name != "client_assertion" {
			filtered = append(filtered, p)
		}
	}
	_, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP: server.FormRequest{Parameters: filtered}, DPoPProof: createDPoPProof(t, generateKey(t), h.now),
	})
	if code := serverErrorCode(t, err); code != server.ErrorInvalidClient {
		t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidClient)
	}
}

func TestExchangeAuthorizationCodeRejectsWrongCodeVerifier(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts"})

	_, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:      server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, "wrong-verifier-wrong-verifier-wrong-verif")},
		DPoPProof: createDPoPProof(t, generateKey(t), h.now),
	})
	if code := serverErrorCode(t, err); code != server.ErrorInvalidGrant {
		t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidGrant)
	}
}

func TestExchangeAuthorizationCodeRejectsWrongRedirectURI(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts"})

	_, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:      server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, "https://attacker.example/callback", testCodeVerifier)},
		DPoPProof: createDPoPProof(t, generateKey(t), h.now),
	})
	if code := serverErrorCode(t, err); code != server.ErrorInvalidGrant {
		t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidGrant)
	}
}

func TestExchangeAuthorizationCodeIsSingleUse(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts"})

	first, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:      server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
		DPoPProof: createDPoPProof(t, generateKey(t), h.now),
	})
	if err != nil {
		t.Fatalf("first ExchangeAuthorizationCode: %v", err)
	}
	if first.AccessToken.Reveal() == "" {
		t.Fatalf("first AccessToken is empty")
	}

	_, err = h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:      server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
		DPoPProof: createDPoPProof(t, generateKey(t), h.now),
	})
	if err == nil {
		t.Fatalf("second ExchangeAuthorizationCode (replayed code) = nil error, want error")
	}
	if code := serverErrorCode(t, err); code != server.ErrorInvalidGrant {
		t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidGrant)
	}
}

func TestExchangeAuthorizationCodeDetectsDPoPReplay(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	code1 := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts"})
	code2 := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts"})

	dpopKey := generateKey(t)
	proof := createDPoPProof(t, dpopKey, h.now)

	if _, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:      server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code1, testRedirectURI, testCodeVerifier)},
		DPoPProof: proof,
	}); err != nil {
		t.Fatalf("first ExchangeAuthorizationCode: %v", err)
	}

	_, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:      server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code2, testRedirectURI, testCodeVerifier)},
		DPoPProof: proof, // reused proof, fresh code
	})
	if err == nil {
		t.Fatalf("ExchangeAuthorizationCode(reused dpop proof) = nil error, want error")
	}
	if code := serverErrorCode(t, err); code != server.ErrorInvalidRequest {
		t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidRequest)
	}
}

func TestExchangeAuthorizationCodeAuditsOutcomes(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts"})

	if _, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:      server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
		DPoPProof: createDPoPProof(t, generateKey(t), h.now),
	}); err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}

	var success int
	for _, e := range h.audit.all() {
		if e.Type == server.AuditEventExchangeAuthorizationCode && e.Outcome == server.AuditOutcomeSuccess {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("success audit events = %d, want 1", success)
	}
}

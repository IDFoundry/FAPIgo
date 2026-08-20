package server_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/internal/dpop"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/internal/token"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
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
	dpopJWKStr := dpopJWK.String()
	validatedAT, err := parsedAT.Validate(&h.serverKey.PublicKey, token.AccessTokenValidatePolicy{
		ExpectedIssuer: testIssuer, ExpectedAudience: testIssuer,
		Algorithm: fapi.ES256, ExpectedThumbprint: &dpopJWKStr,
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

// FAPI2SPFinalPAREnsurePKCECodeVerifierRequired in the OIDF conformance
// suite requires an omitted code_verifier be rejected as invalid_grant,
// not invalid_request: RFC 7636 §4.6 treats a code_verifier problem as
// a grant-validity failure, the same as a mismatched one, not a
// malformed-request one.
func TestExchangeAuthorizationCodeRejectsMissingCodeVerifier(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts"})

	_, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:      server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, "")},
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

// completeAuthorizationWithDPoPJKT mirrors completeSuccessfulAuthorization
// but adds a "dpop_jkt" (RFC 9449 §10) authorization parameter, so tests
// can exercise ExchangeAuthorizationCode's binding check against it.
func completeAuthorizationWithDPoPJKT(t *testing.T, h harness, jkt string) string {
	t.Helper()
	params := []server.FormParameter{
		formParam("client_assertion", h.clientAssertion(t)),
		formParam("client_assertion_type", clientassertion.AssertionType),
		formParam("response_type", "code"),
		formParam("redirect_uri", testRedirectURI),
		formParam("scope", "openid accounts"),
		formParam("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
		formParam("code_challenge_method", "S256"),
		formParam("state", "opaque-state"),
		formParam("dpop_jkt", jkt),
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
		Handle: required.Handle,
		Result: server.Authorize(subject, authCtx, server.GrantedAuthorization{Scope: []string{"openid", "accounts"}}),
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

func TestExchangeAuthorizationCodeAcceptsMatchingDPoPJKT(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	boundKey := generateKey(t)
	boundThumbprint, err := jwkThumbprintFor(boundKey)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	code := completeAuthorizationWithDPoPJKT(t, h, boundThumbprint.String())

	_, err = h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:      server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
		DPoPProof: createDPoPProof(t, boundKey, h.now),
	})
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
}

func TestExchangeAuthorizationCodeRejectsMismatchedDPoPJKT(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	boundKey := generateKey(t)
	boundThumbprint, err := jwkThumbprintFor(boundKey)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	code := completeAuthorizationWithDPoPJKT(t, h, boundThumbprint.String())

	// Present a different DPoP key at the token endpoint than the one
	// declared via dpop_jkt at authorization time (RFC 9449 §10).
	_, err = h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:      server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
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

// TestExchangeAuthorizationCodeReuseRevokesAccessToken exercises RFC
// 6749 §4.1.2's "SHOULD revoke (if possible) all tokens previously
// issued based on that authorization code": a detected code-reuse
// attempt must call Dependencies.Revocation.Revoke with the jti of the
// access token the first, legitimate exchange issued.
func TestExchangeAuthorizationCodeReuseRevokesAccessToken(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts"})

	first, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:      server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
		DPoPProof: createDPoPProof(t, generateKey(t), h.now),
	})
	if err != nil {
		t.Fatalf("first ExchangeAuthorizationCode: %v", err)
	}
	parsedAT, err := token.ParseAccessToken(first.AccessToken.Reveal())
	if err != nil {
		t.Fatalf("ParseAccessToken: %v", err)
	}
	validatedAT, err := parsedAT.Validate(&h.serverKey.PublicKey, token.AccessTokenValidatePolicy{
		ExpectedIssuer: testIssuer, ExpectedAudience: testIssuer,
		Algorithm: fapi.ES256, Now: h.now, MaxLifetime: 10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Validate access token: %v", err)
	}
	if validatedAT.JTI == "" {
		t.Fatalf("issued access token has an empty JTI")
	}

	if len(h.revocation.all()) != 0 {
		t.Fatalf("Revoke called before any reuse was detected: %v", h.revocation.all())
	}

	_, err = h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:      server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
		DPoPProof: createDPoPProof(t, generateKey(t), h.now),
	})
	if err == nil {
		t.Fatalf("second ExchangeAuthorizationCode (replayed code) = nil error, want error")
	}

	revoked := h.revocation.all()
	if len(revoked) != 1 || revoked[0] != validatedAT.JTI {
		t.Fatalf("Revoke calls = %v, want exactly [%q]", revoked, validatedAT.JTI)
	}
}

// TestExchangeAuthorizationCodeReuseRevokesRefreshToken covers the same
// RFC 6749 §4.1.2 "all tokens" requirement for the refresh-token half:
// when the original exchange also granted offline_access, a detected
// reuse must revoke that refresh token too, not just the access token.
func TestExchangeAuthorizationCodeReuseRevokesRefreshToken(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts", "offline_access"})

	first, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:      server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
		DPoPProof: createDPoPProof(t, generateKey(t), h.now),
	})
	if err != nil {
		t.Fatalf("first ExchangeAuthorizationCode: %v", err)
	}
	if !first.HasRefreshToken || first.RefreshToken.Reveal() == "" {
		t.Fatalf("expected a refresh token since scope included offline_access")
	}

	if _, err := h.server.RefreshAccessToken(context.Background(), server.RefreshTokenRequest{
		HTTP:      server.FormRequest{Parameters: refreshFormParams(h.clientAssertion(t), first.RefreshToken.Reveal(), "")},
		DPoPProof: createDPoPProof(t, generateKey(t), h.now),
	}); err != nil {
		t.Fatalf("refresh before reuse was detected: %v", err)
	}

	if _, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:      server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
		DPoPProof: createDPoPProof(t, generateKey(t), h.now),
	}); err == nil {
		t.Fatalf("second ExchangeAuthorizationCode (replayed code) = nil error, want error")
	}

	if _, err := h.server.RefreshAccessToken(context.Background(), server.RefreshTokenRequest{
		HTTP:      server.FormRequest{Parameters: refreshFormParams(h.clientAssertion(t), first.RefreshToken.Reveal(), "")},
		DPoPProof: createDPoPProof(t, generateKey(t), h.now),
	}); err == nil {
		t.Fatalf("refresh after code reuse was detected = nil error, want error (refresh token should be revoked)")
	}
}

// newHarnessWithOpaqueAccessTokens is newHarness's counterpart wired
// to server.OpaqueAccessTokens instead of the default JWTAccessTokens,
// for tests confirming the revocation-on-reuse feature and the
// pluggable access-token format actually work together — the two were
// each tested independently when they were built, never against each
// other. Returns the shared storage.AccessTokenStore too, so a test
// can also build a matching resource.OpaqueAccessTokens verifier.
func newHarnessWithOpaqueAccessTokens(t *testing.T, profile server.Profile, allowRequestObjects bool) (harness, *memstore.AccessTokenStore) {
	t.Helper()
	now := time.Now()
	key := generateKey(t)
	serverKey := generateKey(t)

	reqObjAlg := fapi.ES256
	if !allowRequestObjects {
		reqObjAlg = 0
	}
	client, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID:                       testClientID,
		RedirectURIs:             []fapi.RegisteredRedirectURI{testRedirectURI},
		ClientAssertionAlgorithm: fapi.ES256,
		RequestObjectAlgorithm:   reqObjAlg,
		AllowedScopes:            []string{"openid", "accounts", "offline_access"},
	})
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}
	issuer, err := fapi.ParseIssuerURL(testIssuer)
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}

	transactions := &fakeTransactionStore{}
	grants := &fakeGrantStore{}
	audit := &fakeAuditSink{}
	revocation := &fakeRevocationSink{}
	store := memstore.NewAccessTokenStore()

	cfg := server.Config{
		Issuer:    issuer,
		Endpoints: testEndpoints(t),
		Profile:   profile,
		Algorithms: server.AlgorithmPolicy{
			ClientAssertion: server.AlgorithmSet{fapi.ES256},
			RequestObject:   server.AlgorithmSet{fapi.ES256},
			JARM:            fapi.ES256,
			IDToken:         fapi.ES256,
		},
		Limits: server.Limits{
			PushedRequestLifetime:      90 * time.Second,
			MaxClientAssertionLifetime: time.Minute,
			MaxRequestObjectLifetime:   time.Minute,
			InteractionLifetime:        5 * time.Minute,
			AuthorizationCodeLifetime:  time.Minute,
			JARMResponseLifetime:       time.Minute,
			AccessTokenLifetime:        5 * time.Minute,
			IDTokenLifetime:            5 * time.Minute,
			RefreshTokenLifetime:       5 * time.Minute,
			MaxDPoPProofAge:            time.Minute,
			MaxClockSkew:               5 * time.Second,
		},
		Assurance: server.AssuranceDevelopment,
	}
	deps := server.Dependencies{
		Clients:      &fakeClientRepository{clients: map[fapi.ClientID]storage.RegisteredClient{testClientID: client}},
		Transactions: transactions,
		Grants:       grants,
		Replay:       &fakeReplayStore{},
		ClientKeys: &fakeClientKeySource{keysByClient: map[fapi.ClientID][]keys.VerificationKey{
			testClientID: {{Algorithm: fapi.ES256, PublicKey: &key.PublicKey}},
		}},
		Keys:         &fakeKeyManager{key: serverKey, keyID: "as-key-1"},
		AccessTokens: server.OpaqueAccessTokens{Store: store},
		Revocation:   revocation,
		Audit:        audit,
		Clock:        fixedClock{now: now},
		Random:       rand.Reader,
	}

	srv, err := server.New(cfg, deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return harness{server: srv, key: key, serverKey: serverKey, transactions: transactions, grants: grants, audit: audit, revocation: revocation, now: now}, store
}

// revocationCheckerFromSink adapts a *fakeRevocationSink
// (server.RevocationSink, an append-only log of Revoke calls) into a
// resource.RevocationChecker, so a test can confirm resource.Verify()
// actually rejects a token this same sink recorded as revoked, without
// needing a second, separately-wired revocation store.
type revocationCheckerFromSink struct {
	sink *fakeRevocationSink
}

func (r revocationCheckerFromSink) IsRevoked(_ context.Context, key string) (bool, error) {
	for _, k := range r.sink.all() {
		if k == key {
			return true, nil
		}
	}
	return false, nil
}

// TestExchangeAuthorizationCodeReuseRevokesOpaqueAccessToken is
// TestExchangeAuthorizationCodeReuseRevokesAccessToken's counterpart
// under OpaqueAccessTokens: the revocation-on-reuse feature (RFC 6749
// §4.1.2, added in an earlier PR) and the pluggable access-token
// format (added in a later PR) were each tested independently when
// built, but never against each other — this confirms the opaque
// token's own hash is what gets recorded and revoked, and that a real
// resource.Verifier, backed by the same storage.AccessTokenStore, is
// actually rejected end to end afterward — not just that Revoke got
// called with the right-looking string.
func TestExchangeAuthorizationCodeReuseRevokesOpaqueAccessToken(t *testing.T) {
	h, store := newHarnessWithOpaqueAccessTokens(t, server.ProfileFAPISecurity, true)
	code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts"})

	dpopKey := generateKey(t)
	first, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:      server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
		DPoPProof: createDPoPProof(t, dpopKey, h.now),
	})
	if err != nil {
		t.Fatalf("first ExchangeAuthorizationCode: %v", err)
	}
	rawAccessToken := first.AccessToken.Reveal()
	if rawAccessToken == "" {
		t.Fatalf("issued access token is empty")
	}
	if _, err := token.ParseAccessToken(rawAccessToken); err == nil {
		t.Fatalf("opaque access token unexpectedly parsed as a JWT")
	}
	tokenHash := sha256.Sum256([]byte(rawAccessToken))
	if _, err := store.LookupAccessToken(context.Background(), storage.AccessTokenLookup{TokenHash: tokenHash}); err != nil {
		t.Fatalf("LookupAccessToken(issued token): %v", err)
	}

	if len(h.revocation.all()) != 0 {
		t.Fatalf("Revoke called before any reuse was detected: %v", h.revocation.all())
	}

	// A real resource.Verifier, backed by the same
	// storage.AccessTokenStore and a RevocationChecker that sees what
	// a later reuse records, must accept the token now (proving any
	// later rejection is actually caused by revocation, not some
	// unrelated setup mistake) ...
	target, err := url.Parse("https://rs.example.com/accounts")
	if err != nil {
		t.Fatalf("parse target url: %v", err)
	}
	verifier, err := resource.NewVerifier(resource.Config{
		Limits: resource.Limits{MaxDPoPProofAge: time.Minute, MaxClockSkew: 5 * time.Second},
	}, resource.Dependencies{
		AccessTokens: resource.OpaqueAccessTokens{Store: store},
		Replay:       memstore.NewReplayStore(),
		Revocation:   revocationCheckerFromSink{sink: h.revocation},
		Clock:        fixedClock{now: h.now},
	})
	if err != nil {
		t.Fatalf("resource.NewVerifier: %v", err)
	}
	verifyOpaqueToken := func(t *testing.T) error {
		t.Helper()
		proof, err := dpop.CreateProof(dpop.ProofRequest{
			Signer: dpopKey, Algorithm: fapi.ES256,
			Method: "GET", URL: target,
			AccessToken: rawAccessToken,
			Now:         h.now,
			Random:      rand.Reader,
		})
		if err != nil {
			t.Fatalf("create dpop proof: %v", err)
		}
		_, err = verifier.Verify(context.Background(), resource.VerifyRequest{
			Method: "GET", URL: target,
			Authorization: "DPoP " + rawAccessToken,
			DPoPProof:     proof,
		})
		return err
	}
	if err := verifyOpaqueToken(t); err != nil {
		t.Fatalf("Verify(not-yet-revoked opaque token): %v", err)
	}

	// ... then trigger the code reuse ...
	if _, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:      server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
		DPoPProof: createDPoPProof(t, generateKey(t), h.now),
	}); err == nil {
		t.Fatalf("second ExchangeAuthorizationCode (replayed code) = nil error, want error")
	}

	wantKey := hex.EncodeToString(tokenHash[:])
	revoked := h.revocation.all()
	if len(revoked) != 1 || revoked[0] != wantKey {
		t.Fatalf("Revoke calls = %v, want exactly [%q]", revoked, wantKey)
	}

	// ... and confirm the exact same verifier now rejects it (a fresh
	// DPoP proof each call — proofs are single-use).
	if err := verifyOpaqueToken(t); err == nil {
		t.Fatalf("Verify(revoked opaque token) = nil error, want error")
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

// issuerKeySourceFromManager adapts a keys.KeyManager to
// keys.IssuerKeySource for tests that need a resource-side verifier —
// resource.JWTAccessTokens.VerifyAccessToken resolves candidate keys
// through this, exactly as cmd/conformance-as's own
// selfIssuerKeySource does for a co-located AS+resource-server
// deployment.
type issuerKeySourceFromManager struct {
	manager keys.KeyManager
}

func (s issuerKeySourceFromManager) ResolveIssuerKeys(ctx context.Context, req keys.IssuerKeyRequest) (keys.IssuerKeySet, error) {
	info, err := s.manager.PublicKey(ctx, keys.AccessTokenSigning, req.Algorithm)
	if err != nil {
		return keys.IssuerKeySet{}, err
	}
	return keys.IssuerKeySet{Keys: []keys.IssuerKey{{KeyID: info.KeyID, Algorithm: req.Algorithm, PublicKey: info.PublicKey}}}, nil
}

// TestJWTAccessTokensRoundTripsThroughResourceVerifier issues an
// access token via server.JWTAccessTokens and confirms
// resource.JWTAccessTokens accepts it and reports the same
// authorization facts — the two default implementations of this
// session's newly pluggable AccessTokenIssuer/AccessTokenVerifier
// boundary must actually interoperate, not just each compile.
func TestJWTAccessTokensRoundTripsThroughResourceVerifier(t *testing.T) {
	signerKey := generateKey(t)
	km := &fakeKeyManager{key: signerKey, keyID: "as-key-1"}
	issuer := server.JWTAccessTokens{Keys: km, Algorithm: fapi.ES256}

	now := time.Now()
	dpopKey := generateKey(t)
	dpopThumbprint, err := jwkThumbprintFor(dpopKey)
	if err != nil {
		t.Fatalf("jwkThumbprintFor: %v", err)
	}

	raw, issueKey, err := issuer.IssueAccessToken(context.Background(), server.AccessTokenParams{
		ClientID: testClientID, Subject: "user-1", Scope: []string{"openid", "accounts"},
		Thumbprint: dpopThumbprint.String(),
		Issuer:     testIssuer, Audience: testIssuer,
		Now: now, Lifetime: 5 * time.Minute, Random: rand.Reader,
	})
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}
	if raw == "" || issueKey == "" {
		t.Fatalf("IssueAccessToken returned empty token or key")
	}

	issuerURL, err := fapi.ParseIssuerURL(testIssuer)
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}
	verifier, err := resource.NewJWTAccessTokens(issuerKeySourceFromManager{manager: km}, issuerURL, testIssuer, fapi.ES256, 5*time.Minute)
	if err != nil {
		t.Fatalf("resource.NewJWTAccessTokens: %v", err)
	}

	validated, err := verifier.VerifyAccessToken(context.Background(), resource.VerifyAccessTokenRequest{
		Raw: raw, Thumbprint: dpopThumbprint.String(), Now: now, MaxClockSkew: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	if validated.Subject != "user-1" {
		t.Fatalf("Subject = %q, want %q", validated.Subject, "user-1")
	}
	if validated.ClientID != testClientID.String() {
		t.Fatalf("ClientID = %q, want %q", validated.ClientID, testClientID)
	}
	if validated.Key != issueKey {
		t.Fatalf("Key = %q, want %q", validated.Key, issueKey)
	}
}

// TestOpaqueAccessTokensRoundTripsThroughResourceVerifier is
// TestJWTAccessTokensRoundTripsThroughResourceVerifier's counterpart
// for the opaque, storage-backed implementation — issued via
// server.OpaqueAccessTokens, verified via resource.OpaqueAccessTokens,
// sharing one storage.AccessTokenStore instance (the co-located
// AS+resource-server deployment shape cmd/conformance-as itself could
// use, per the design plan's Tier 1).
func TestOpaqueAccessTokensRoundTripsThroughResourceVerifier(t *testing.T) {
	store := memstore.NewAccessTokenStore()
	issuer := server.OpaqueAccessTokens{Store: store}
	verifier := resource.OpaqueAccessTokens{Store: store}

	now := time.Now()
	dpopKey := generateKey(t)
	dpopThumbprint, err := jwkThumbprintFor(dpopKey)
	if err != nil {
		t.Fatalf("jwkThumbprintFor: %v", err)
	}

	raw, issueKey, err := issuer.IssueAccessToken(context.Background(), server.AccessTokenParams{
		ClientID: testClientID, Subject: "user-1", Scope: []string{"openid", "accounts"},
		Thumbprint: dpopThumbprint.String(),
		Now:        now, Lifetime: 5 * time.Minute, Random: rand.Reader,
	})
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}
	if raw == "" || issueKey == "" {
		t.Fatalf("IssueAccessToken returned empty token or key")
	}
	// An opaque token has nothing embedded in it — unlike the JWT
	// case, its own raw value carries no claims to inspect.
	if _, err := token.ParseAccessToken(raw); err == nil {
		t.Fatalf("opaque token unexpectedly parsed as a JWT")
	}

	validated, err := verifier.VerifyAccessToken(context.Background(), resource.VerifyAccessTokenRequest{
		Raw: raw, Thumbprint: dpopThumbprint.String(), Now: now, MaxClockSkew: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	if validated.Subject != "user-1" {
		t.Fatalf("Subject = %q, want %q", validated.Subject, "user-1")
	}
	if validated.ClientID != testClientID.String() {
		t.Fatalf("ClientID = %q, want %q", validated.ClientID, testClientID)
	}
	if validated.Key != issueKey {
		t.Fatalf("Key = %q, want %q", validated.Key, issueKey)
	}

	// Wrong DPoP key must be rejected.
	if _, err := verifier.VerifyAccessToken(context.Background(), resource.VerifyAccessTokenRequest{
		Raw: raw, Thumbprint: "wrong-thumbprint", Now: now, MaxClockSkew: 5 * time.Second,
	}); err == nil {
		t.Fatalf("VerifyAccessToken(wrong thumbprint) = nil error, want error")
	}

	// Unknown token must be rejected.
	if _, err := verifier.VerifyAccessToken(context.Background(), resource.VerifyAccessTokenRequest{
		Raw: "never-issued", Thumbprint: dpopThumbprint.String(), Now: now, MaxClockSkew: 5 * time.Second,
	}); err == nil {
		t.Fatalf("VerifyAccessToken(unknown token) = nil error, want error")
	}
}

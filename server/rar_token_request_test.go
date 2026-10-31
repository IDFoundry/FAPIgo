package server_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/server"
)

// Two payments granted in full, for the token request tests below to
// narrow.
const (
	rarTokenRequestGranted = `[{"type":"payment","actions":["approve"],"amount":"SGD 500.00"},{"type":"payment","actions":["approve"],"amount":"SGD 10.00"}]`
	rarTokenRequestSmall   = `[{"type":"payment","actions":["approve"],"amount":"SGD 10.00"}]`
	rarTokenRequestWider   = `[{"type":"payment","actions":["approve"],"amount":"SGD 99999.00"}]`
	rarTokenRequestBadJSON = `{not json`
)

// rarTokenRequestHarness is a RAR harness whose client may use the
// "payment" type under both grants.
func rarTokenRequestHarness(t *testing.T) harness {
	t.Helper()
	allow := fakeRARPolicy{allow: map[string]bool{"payment": true}}
	return newHarnessWithRAR(t, server.ProfileFAPISecurity, newTestRARRegistry(t), allow, allow)
}

// rarGrantAll returns every detail of values as granted objects.
func rarGrantAll(t *testing.T, values extension.RARValues) []json.RawMessage {
	t.Helper()
	details, err := extension.RARGet(values, paymentRARDef)
	if err != nil {
		t.Fatalf("RARGet: %v", err)
	}
	granted := make([]json.RawMessage, 0, len(details))
	for _, d := range details {
		granted = append(granted, mustMarshal(t, d.Fields))
	}
	return granted
}

// rarIssueCode pushes a request for rarTokenRequestGranted with scope
// "openid accounts offline_access", grants all of it, and returns the
// authorization code.
func rarIssueCode(t *testing.T, h harness) string {
	t.Helper()
	return rarIssueCodeFor(t, h, rarTokenRequestGranted)
}

// rarIssueCodeFor is rarIssueCode for a request for details.
func rarIssueCodeFor(t *testing.T, h harness, details string) string {
	t.Helper()
	push, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_assertion", h.clientAssertion(t)),
			formParam("client_assertion_type", clientassertion.AssertionType),
			formParam("response_type", "code"),
			formParam("redirect_uri", testRedirectURI),
			formParam("scope", "openid accounts offline_access"),
			formParam("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
			formParam("code_challenge_method", "S256"),
			formParam("state", "opaque-state"),
			formParam("authorization_details", details),
		}},
	})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
	action, err := h.server.BeginAuthorization(context.Background(), server.BeginAuthorizationRequest{RequestURI: push.RequestURI.String(), ClientID: testClientID})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	interaction := action.(server.InteractionRequired)
	subject, authCtx := rarSubjectAndAuthCtx(t, h.now)
	result, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
		Handle: interaction.Handle,
		Result: server.Authorize(subject, authCtx, server.GrantedAuthorization{
			Scope:                []string{"openid", "accounts", "offline_access"},
			AuthorizationDetails: rarGrantAll(t, interaction.Interaction.AuthorizationDetails),
		}),
	})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	dest := result.(server.AuthorizationRedirect).Destination().URL()
	return dest.Query().Get("code")
}

// rarExchangeCode exchanges code, adding authorization_details unless
// details is nil.
func rarExchangeCode(t *testing.T, h harness, code string, details *string) (server.TokenResult, error) {
	t.Helper()
	params := exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)
	if details != nil {
		params = append(params, formParam("authorization_details", *details))
	}
	return h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:       server.FormRequest{Parameters: params},
		DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
	})
}

// assertIssuedAuthorizationDetails checks that both the token response
// and the access token's own claim carry exactly want (nil: neither
// carries any).
func assertIssuedAuthorizationDetails(t *testing.T, h harness, result server.TokenResult, want []testPaymentDetail) {
	t.Helper()
	if want == nil {
		if len(result.AuthorizationDetails) != 0 {
			t.Fatalf("TokenResult.AuthorizationDetails = %s, want none", result.AuthorizationDetails)
		}
		return
	}
	assertPaymentDetails(t, "TokenResult.AuthorizationDetails", result.AuthorizationDetails, want)
	claim := authorizationDetailsAccessTokenClaim(t, result.AccessToken.Reveal(), &h.serverKey.PublicKey)
	assertPaymentDetails(t, "access token authorization_details claim", claim, want)
}

func assertPaymentDetails(t *testing.T, what string, raw json.RawMessage, want []testPaymentDetail) {
	t.Helper()
	var got []testPaymentDetail
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("%s: unmarshal %s: %v", what, raw, err)
	}
	if len(got) != len(want) {
		t.Fatalf("%s = %s, want %d objects", what, raw, len(want))
	}
	for i := range want {
		if got[i].Amount != want[i].Amount {
			t.Fatalf("%s = %s, want amounts %+v", what, raw, want)
		}
	}
}

func assertInvalidAuthorizationDetails(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("token request succeeded, want invalid_authorization_details")
	}
	if code := serverErrorCode(t, err); code != server.ErrorInvalidAuthorizationDetails {
		t.Fatalf("error code = %q, want %q (%v)", code, server.ErrorInvalidAuthorizationDetails, err)
	}
}

var (
	rarBothPayments = []testPaymentDetail{{Amount: "SGD 500.00"}, {Amount: "SGD 10.00"}}
	rarSmallPayment = []testPaymentDetail{{Amount: "SGD 10.00"}}
)

func rarParam(s string) *string { return &s }

// RFC 9396 §6: a token request's authorization_details asks for an access
// token with those details, which the AS checks the grant allows, refusing
// with invalid_authorization_details otherwise; §7: the token response
// returns what the access token was assigned.
func TestExchangeAuthorizationCodeNarrowsAuthorizationDetails(t *testing.T) {
	h := rarTokenRequestHarness(t)
	for _, tc := range []struct {
		name    string
		details *string
		want    []testPaymentDetail
	}{
		{"absent", nil, rarBothPayments},
		{"narrowed", rarParam(rarTokenRequestSmall), rarSmallPayment},
		{"all", rarParam(rarTokenRequestGranted), rarBothPayments},
		{"empty", rarParam(`[]`), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := rarExchangeCode(t, h, rarIssueCode(t, h), tc.details)
			if err != nil {
				t.Fatalf("ExchangeAuthorizationCode: %v", err)
			}
			assertIssuedAuthorizationDetails(t, h, result, tc.want)
		})
	}
}

func TestExchangeAuthorizationCodeRefusesWiderAuthorizationDetails(t *testing.T) {
	h := rarTokenRequestHarness(t)
	for name, details := range map[string]string{
		"wider":      rarTokenRequestWider,
		"duplicated": `[{"type":"payment","actions":["approve"],"amount":"SGD 10.00"},{"type":"payment","actions":["approve"],"amount":"SGD 10.00"}]`,
		"unknown":    `[{"type":"other"}]`,
		"bad field":  `[{"type":"payment","actions":["approve"],"extra":true}]`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := rarExchangeCode(t, h, rarIssueCode(t, h), &details)
			assertInvalidAuthorizationDetails(t, err)
		})
	}
}

// A malformed authorization_details is refused before the code is
// redeemed, so the client can still exchange it.
func TestExchangeAuthorizationCodeMalformedAuthorizationDetailsKeepsCode(t *testing.T) {
	h := rarTokenRequestHarness(t)
	code := rarIssueCode(t, h)
	_, err := rarExchangeCode(t, h, code, rarParam(rarTokenRequestBadJSON))
	assertInvalidAuthorizationDetails(t, err)
	if _, err := rarExchangeCode(t, h, code, nil); err != nil {
		t.Fatalf("ExchangeAuthorizationCode after a malformed request: %v", err)
	}
}

func TestExchangeAuthorizationCodeRefusesAuthorizationDetailsWithoutRAR(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, false)
	code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts"})
	_, err := rarExchangeCode(t, h, code, rarParam(rarTokenRequestSmall))
	assertInvalidAuthorizationDetails(t, err)
}

// rarRefresh refreshes refreshToken, adding authorization_details unless
// details is nil.
func rarRefresh(t *testing.T, h harness, refreshToken string, details *string) (server.TokenResult, error) {
	t.Helper()
	params := refreshFormParams(h.clientAssertion(t), refreshToken, "")
	if details != nil {
		params = append(params, formParam("authorization_details", *details))
	}
	return h.server.RefreshAccessToken(context.Background(), server.RefreshTokenRequest{
		HTTP:       server.FormRequest{Parameters: params},
		DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
	})
}

// The refresh token keeps the whole grant whatever the first access token
// was narrowed to, and each refresh may narrow again.
func TestRefreshAccessTokenNarrowsAuthorizationDetails(t *testing.T) {
	h := rarTokenRequestHarness(t)
	first, err := rarExchangeCode(t, h, rarIssueCode(t, h), rarParam(rarTokenRequestSmall))
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	if !first.HasRefreshToken {
		t.Fatal("no refresh token issued")
	}
	refreshToken := first.RefreshToken.Reveal()

	for _, tc := range []struct {
		name    string
		details *string
		want    []testPaymentDetail
	}{
		{"absent", nil, rarBothPayments},
		{"narrowed", rarParam(rarTokenRequestSmall), rarSmallPayment},
		{"empty", rarParam(`[]`), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := rarRefresh(t, h, refreshToken, tc.details)
			if err != nil {
				t.Fatalf("RefreshAccessToken: %v", err)
			}
			assertIssuedAuthorizationDetails(t, h, result, tc.want)
		})
	}
	for name, details := range map[string]string{"wider": rarTokenRequestWider, "malformed": rarTokenRequestBadJSON} {
		t.Run(name, func(t *testing.T) {
			_, err := rarRefresh(t, h, refreshToken, &details)
			assertInvalidAuthorizationDetails(t, err)
		})
	}
}

// rarApproveBackchannel begins a CIBA request for rarTokenRequestGranted,
// grants all of it, and returns the auth_req_id.
func rarApproveBackchannel(t *testing.T, h harness) string {
	t.Helper()
	params := standardBackchannelParams(t)
	params["authorization_details"] = json.RawMessage(rarTokenRequestGranted)
	required := beginBackchannel(t, h, params)
	subject, authCtx := rarSubjectAndAuthCtx(t, h.now)
	if err := h.server.CompleteBackchannelAuthentication(context.Background(), server.CompleteBackchannelAuthenticationRequest{
		Handle: required.Handle,
		Result: server.Authorize(subject, authCtx, server.GrantedAuthorization{
			Scope:                []string{"openid", "accounts"},
			AuthorizationDetails: rarGrantAll(t, required.Interaction.AuthorizationDetails),
		}),
	}); err != nil {
		t.Fatalf("CompleteBackchannelAuthentication: %v", err)
	}
	return required.AuthReqID.String()
}

func rarExchangeBackchannel(t *testing.T, h harness, authReqID string, details *string) (server.TokenResult, error) {
	t.Helper()
	params := []server.FormParameter{
		formParam("client_assertion", h.clientAssertion(t)),
		formParam("client_assertion_type", clientassertion.AssertionType),
		formParam("grant_type", server.CIBAGrantType),
		formParam("auth_req_id", authReqID),
	}
	if details != nil {
		params = append(params, formParam("authorization_details", *details))
	}
	return h.server.ExchangeBackchannelAuthentication(context.Background(), server.BackchannelTokenExchangeRequest{
		HTTP:       server.FormRequest{Parameters: params},
		DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
	})
}

func TestExchangeBackchannelAuthenticationNarrowsAuthorizationDetails(t *testing.T) {
	h := rarTokenRequestHarness(t)
	result, err := rarExchangeBackchannel(t, h, rarApproveBackchannel(t, h), rarParam(rarTokenRequestSmall))
	if err != nil {
		t.Fatalf("ExchangeBackchannelAuthentication: %v", err)
	}
	assertIssuedAuthorizationDetails(t, h, result, rarSmallPayment)

	_, err = rarExchangeBackchannel(t, h, rarApproveBackchannel(t, h), rarParam(rarTokenRequestWider))
	assertInvalidAuthorizationDetails(t, err)
}

// A malformed authorization_details is refused before the approval is
// polled, so the client can still collect it.
func TestExchangeBackchannelAuthenticationMalformedAuthorizationDetailsKeepsApproval(t *testing.T) {
	h := rarTokenRequestHarness(t)
	authReqID := rarApproveBackchannel(t, h)
	_, err := rarExchangeBackchannel(t, h, authReqID, rarParam(rarTokenRequestBadJSON))
	assertInvalidAuthorizationDetails(t, err)
	result, err := rarExchangeBackchannel(t, h, authReqID, nil)
	if err != nil {
		t.Fatalf("ExchangeBackchannelAuthentication after a malformed request: %v", err)
	}
	assertIssuedAuthorizationDetails(t, h, result, rarBothPayments)
}

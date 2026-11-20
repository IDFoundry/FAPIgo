package server_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/server"
)

// scopedDetail authorizes, more narrowly, what the scope it names would
// authorize on its own, as OpenID4VCI 1.0 §5.1.2's openid_credential
// object does a credential configuration's scope: leaving it out of an
// access token that keeps that scope widens the token.
type scopedDetail struct {
	Type   string   `json:"type"`
	Scope  string   `json:"scope"`
	Claims []string `json:"claims,omitempty"`
}

// scopedRARDef refuses to leave out an object whose scope the access
// token still carries.
var scopedRARDef = extension.RARDefinition[scopedDetail]{
	Type: "scoped", MaxObjects: 3, MaxBytesPerObject: 512,
	ValidateOmission: func(granted scopedDetail, scope []string) error {
		if slices.Contains(scope, granted.Scope) {
			return errors.New("the access token keeps the scope this object narrows")
		}
		return nil
	},
}

// The harness's requests ask for scope "openid accounts offline_access":
// the "accounts" object narrows a scope the access token carries, the
// "payments" object one it doesn't.
const (
	scopedAccountsAndPayments = `[{"type":"scoped","scope":"accounts","claims":["balance"]},{"type":"scoped","scope":"payments"}]`
	scopedAccounts            = `[{"type":"scoped","scope":"accounts","claims":["balance"]}]`
	scopedPayments            = `[{"type":"scoped","scope":"payments"}]`
)

const omissionRefusedDescription = "authorization_details leaves out a granted object this access token must carry"

// scopedHarness is a RAR harness registering scopedRARDef, whose client
// may use its type under both grants.
func scopedHarness(t *testing.T) harness {
	t.Helper()
	registry, err := extension.NewRARRegistry(4096, 4, scopedRARDef)
	if err != nil {
		t.Fatalf("NewRARRegistry: %v", err)
	}
	allow := fakeRARPolicy{allow: map[string]bool{"scoped": true}}
	return newHarnessWithRARTypes(t, server.ProfileFAPISecurity, registry, allow, allow, []string{"scoped"})
}

// issueScopedCode requests and grants scopedAccountsAndPayments, with
// scope "openid accounts offline_access", and returns the authorization
// code.
func issueScopedCode(t *testing.T, h harness) string {
	t.Helper()
	interaction := pushAndBeginAuthorization(t, h, scopedAccountsAndPayments)
	subject, authCtx := rarSubjectAndAuthCtx(t, h.now)
	result, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
		Handle: interaction.Handle,
		Result: server.Authorize(subject, authCtx, server.GrantedAuthorization{
			Scope:                []string{"openid", "accounts", "offline_access"},
			AuthorizationDetails: rawDetails(t, scopedAccountsAndPayments),
		}),
	})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	dest := result.(server.AuthorizationRedirect).Destination().URL()
	return dest.Query().Get("code")
}

// approveScopedBackchannel begins a CIBA request for
// scopedAccountsAndPayments, grants all of it with scope "openid
// accounts", and returns the auth_req_id.
func approveScopedBackchannel(t *testing.T, h harness) string {
	t.Helper()
	params := standardBackchannelParams(t)
	params["authorization_details"] = json.RawMessage(scopedAccountsAndPayments)
	required := beginBackchannel(t, h, params)
	subject, authCtx := rarSubjectAndAuthCtx(t, h.now)
	if err := h.server.CompleteBackchannelAuthentication(context.Background(), server.CompleteBackchannelAuthenticationRequest{
		Handle: required.Handle,
		Result: server.Authorize(subject, authCtx, server.GrantedAuthorization{
			Scope:                []string{"openid", "accounts"},
			AuthorizationDetails: rawDetails(t, scopedAccountsAndPayments),
		}),
	}); err != nil {
		t.Fatalf("CompleteBackchannelAuthentication: %v", err)
	}
	return required.AuthReqID.String()
}

// assertOmissionRefused checks err is the invalid_authorization_details
// of a granted object left out that its ValidateOmission refused.
func assertOmissionRefused(t *testing.T, err error) {
	t.Helper()
	assertInvalidAuthorizationDetails(t, err)
	if got := serverErrorDescription(t, err); got != omissionRefusedDescription {
		t.Fatalf("error_description = %q, want %q", got, omissionRefusedDescription)
	}
	if !errors.Is(err, extension.ErrRAROmissionRefused) {
		t.Fatalf("error = %v, want it to wrap extension.ErrRAROmissionRefused", err)
	}
}

// assertIssuedScopes checks that both the token response and the access
// token's own claim carry exactly the objects of want, by scope (none:
// neither carries any).
func assertIssuedScopes(t *testing.T, h harness, result server.TokenResult, want ...string) {
	t.Helper()
	if len(want) == 0 {
		if len(result.AuthorizationDetails) != 0 {
			t.Fatalf("TokenResult.AuthorizationDetails = %s, want none", result.AuthorizationDetails)
		}
		return
	}
	for what, raw := range map[string]json.RawMessage{
		"TokenResult.AuthorizationDetails":         result.AuthorizationDetails,
		"access token authorization_details claim": authorizationDetailsAccessTokenClaim(t, result.AccessToken.Reveal(), &h.serverKey.PublicKey),
	} {
		var got []scopedDetail
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("%s: unmarshal %s: %v", what, raw, err)
		}
		var scopes []string
		for _, d := range got {
			scopes = append(scopes, d.Scope)
		}
		if !slices.Equal(scopes, want) {
			t.Fatalf("%s = %s, want the objects for %q", what, raw, want)
		}
	}
}

// RFC 9396 §6.1 lets a token request leave out granted objects, which a
// RARDefinition.ValidateOmission may refuse when the access token keeps
// the scope an object narrows, as OpenID4VCI 1.0 §5.1.2 has the object
// govern then. The authorization code exchange is refused for an empty
// array, and for leaving out the "accounts" object, while leaving out
// the "payments" object, whose scope the token lacks, is allowed.
func TestExchangeAuthorizationCodeAsksBeforeLeavingOutAGrantedObject(t *testing.T) {
	h := scopedHarness(t)
	for name, details := range map[string]string{"empty": `[]`, "accounts left out": scopedPayments} {
		t.Run(name, func(t *testing.T) {
			_, err := rarExchangeCode(t, h, issueScopedCode(t, h), &details)
			assertOmissionRefused(t, err)
		})
	}
	for _, tc := range []struct {
		name    string
		details *string
		want    []string
	}{
		{"absent", nil, []string{"accounts", "payments"}},
		{"all", rarParam(scopedAccountsAndPayments), []string{"accounts", "payments"}},
		{"payments left out", rarParam(scopedAccounts), []string{"accounts"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := rarExchangeCode(t, h, issueScopedCode(t, h), tc.details)
			if err != nil {
				t.Fatalf("ExchangeAuthorizationCode: %v", err)
			}
			assertIssuedScopes(t, h, result, tc.want...)
		})
	}
}

// At a refresh, ValidateOmission gets the scope the refreshed access
// token will carry, which a scope parameter may narrow: an empty array
// is refused while the token keeps "accounts", and allowed once the
// refresh drops it.
func TestRefreshAccessTokenAsksBeforeLeavingOutAGrantedObject(t *testing.T) {
	h := scopedHarness(t)
	first, err := rarExchangeCode(t, h, issueScopedCode(t, h), nil)
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	if !first.HasRefreshToken {
		t.Fatal("no refresh token issued")
	}
	refresh := func(scope, details string) (server.TokenResult, error) {
		t.Helper()
		params := append(refreshFormParams(h.clientAssertion(t), first.RefreshToken.Reveal(), scope), formParam("authorization_details", details))
		return h.server.RefreshAccessToken(context.Background(), server.RefreshTokenRequest{
			HTTP:       server.FormRequest{Parameters: params},
			DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
		})
	}

	_, err = refresh("", `[]`)
	assertOmissionRefused(t, err)
	_, err = refresh("openid accounts offline_access", scopedPayments)
	assertOmissionRefused(t, err)

	result, err := refresh("openid offline_access", `[]`)
	if err != nil {
		t.Fatalf("RefreshAccessToken without accounts, leaving out every object: %v", err)
	}
	assertIssuedScopes(t, h, result)
	if result.Scope != "openid offline_access" {
		t.Fatalf("refreshed scope = %q, want %q", result.Scope, "openid offline_access")
	}

	result, err = refresh("", scopedAccounts)
	if err != nil {
		t.Fatalf("RefreshAccessToken leaving out payments: %v", err)
	}
	assertIssuedScopes(t, h, result, "accounts")
}

// Consent can't grant authorization_details to a request that asked for
// none: there is nothing for them to narrow.
func TestCompleteAuthorizationRefusesDetailsForARequestWithout(t *testing.T) {
	h := scopedHarness(t)
	required, ok := pushAndBegin(t, h, nil).(server.InteractionRequired)
	if !ok {
		t.Fatal("BeginAuthorization didn't ask for an interaction")
	}
	subject, authCtx := rarSubjectAndAuthCtx(t, h.now)
	result, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
		Handle: required.Handle,
		Result: server.Authorize(subject, authCtx, server.GrantedAuthorization{
			Scope:                required.Interaction.Scope,
			AuthorizationDetails: rawDetails(t, scopedAccounts),
		}),
	})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	local, ok := result.(server.AuthorizationLocalError)
	if !ok {
		t.Fatalf("CompleteAuthorization granting unrequested details = %T, want server.AuthorizationLocalError", result)
	}
	if code := serverErrorCode(t, local.Error); code != server.ErrorInvalidRequest {
		t.Fatalf("CompleteAuthorization granting unrequested details: error code = %q, want %q", code, server.ErrorInvalidRequest)
	}
}

// The CIBA token request is held to ValidateOmission the same way, with
// the grant's scope.
func TestExchangeBackchannelAuthenticationAsksBeforeLeavingOutAGrantedObject(t *testing.T) {
	h := scopedHarness(t)
	_, err := rarExchangeBackchannel(t, h, approveScopedBackchannel(t, h), rarParam(`[]`))
	assertOmissionRefused(t, err)

	result, err := rarExchangeBackchannel(t, h, approveScopedBackchannel(t, h), rarParam(scopedAccounts))
	if err != nil {
		t.Fatalf("ExchangeBackchannelAuthentication leaving out payments: %v", err)
	}
	assertIssuedScopes(t, h, result, "accounts")
}

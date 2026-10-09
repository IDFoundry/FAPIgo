package server_test

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/server"
)

// acrClaims is a "claims" parameter requesting acr for the ID token with
// the given entry.
func acrClaims(entry string) string {
	return `{"id_token":{"acr":` + entry + `}}`
}

// authorizedWithACR authorizes user-1 now, authenticated at acr.
func authorizedWithACR(t *testing.T, h harness, acr string) server.InteractionResult {
	t.Helper()
	subjectID, err := server.NewSubjectID("user-1")
	if err != nil {
		t.Fatal(err)
	}
	subject, err := server.NewAuthenticatedSubject(subjectID)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := server.NewAuthenticationContext(h.now, acr, []string{"pwd"})
	if err != nil {
		t.Fatal(err)
	}
	return server.Authorize(subject, auth, server.GrantedAuthorization{Scope: []string{"openid", "accounts"}})
}

// forgetEssentialACR rewrites every pending interaction's stored request
// without essential_acr_values, as a record written before it existed
// is.
func forgetEssentialACR(t *testing.T, h harness) {
	t.Helper()
	h.transactions.mu.Lock()
	defer h.transactions.mu.Unlock()
	for handle, pending := range h.transactions.byHandle {
		var record map[string]json.RawMessage
		if err := json.Unmarshal(pending.interaction.Request, &record); err != nil {
			t.Fatal(err)
		}
		if _, ok := record["essential_acr_values"]; !ok {
			t.Fatal("the stored request has no essential_acr_values to forget")
		}
		delete(record, "essential_acr_values")
		raw, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		pending.interaction.Request = raw
		h.transactions.byHandle[handle] = pending
	}
}

// TestCompleteAuthorizationEnforcesEssentialACR covers OIDC Core
// §5.5.1.1: an essential acr request with a value or values must be met,
// or the outcome is a failed authentication (login_required, no code);
// a voluntary request, acr_values, and a record written before the
// requirement was kept aren't enforced.
func TestCompleteAuthorizationEnforcesEssentialACR(t *testing.T) {
	for _, tc := range []essentialACRCase{
		{name: "values, met", claims: acrClaims(`{"essential":true,"values":["urn:gold","urn:silver"]}`), acr: "urn:silver", wantValues: []string{"urn:gold", "urn:silver"}},
		{name: "values, not met", claims: acrClaims(`{"essential":true,"values":["urn:gold"]}`), acr: "urn:silver", wantError: "login_required", wantValues: []string{"urn:gold"}},
		{name: "single value, met", claims: acrClaims(`{"essential":true,"value":"urn:gold"}`), acr: "urn:gold", wantValues: []string{"urn:gold"}},
		{name: "single value, not met", claims: acrClaims(`{"essential":true,"value":"urn:gold"}`), acr: "urn:bronze", wantError: "login_required", wantValues: []string{"urn:gold"}},
		{name: "no acr reported", claims: acrClaims(`{"essential":true,"value":"urn:gold"}`), acr: "", wantError: "login_required", wantValues: []string{"urn:gold"}},
		{name: "voluntary", claims: acrClaims(`{"values":["urn:gold"]}`), acr: "urn:bronze"},
		{name: "essential false", claims: acrClaims(`{"essential":false,"value":"urn:gold"}`), acr: "urn:bronze"},
		{name: "essential without values", claims: acrClaims(`{"essential":true}`), acr: "urn:bronze"},
		{name: "acr_values only", acrValues: "urn:gold", acr: "urn:bronze"},
		{name: "record without the requirement", claims: acrClaims(`{"essential":true,"value":"urn:gold"}`), acr: "urn:bronze", legacy: true, wantValues: []string{"urn:gold"}},
	} {
		t.Run(tc.name, func(t *testing.T) { runEssentialACRCase(t, tc) })
	}
}

// essentialACRCase is one TestCompleteAuthorizationEnforcesEssentialACR
// case.
type essentialACRCase struct {
	name       string
	claims     string
	acrValues  string
	acr        string
	legacy     bool
	wantError  string
	wantValues []string
}

// runEssentialACRCase pushes tc's request, checks the interaction's
// EssentialACRValues, completes it with tc.acr and checks the redirect.
func runEssentialACRCase(t *testing.T, tc essentialACRCase) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	extra := map[string]string{}
	if tc.claims != "" {
		extra["claims"] = tc.claims
	}
	if tc.acrValues != "" {
		extra["acr_values"] = tc.acrValues
	}
	required := interactionFor(t, h, extra)
	if !slices.Equal(required.Interaction.EssentialACRValues, tc.wantValues) {
		t.Errorf("EssentialACRValues = %q, want %q", required.Interaction.EssentialACRValues, tc.wantValues)
	}
	if tc.legacy {
		forgetEssentialACR(t, h)
	}
	completed, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{Handle: required.Handle, Result: authorizedWithACR(t, h, tc.acr)})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	redirect, ok := completed.(server.AuthorizationRedirect)
	if !ok {
		t.Fatalf("result = %T, want a redirect", completed)
	}
	dest := redirect.Destination().URL()
	q := dest.Query()
	if q.Get("error") != tc.wantError {
		t.Errorf("error = %q (%s), want %q", q.Get("error"), q.Get("error_description"), tc.wantError)
	}
	if (q.Get("code") != "") != (tc.wantError == "") {
		t.Errorf("code present = %v, want %v", q.Get("code") != "", tc.wantError == "")
	}
	if tc.wantError != "" && len(h.grants.all()) != 0 {
		t.Error("a code was stored for a refused completion")
	}
}

// TestInteractionRequestEncodingKeepsEssentialACR: the requirement
// survives the encoding the application stores between instances.
func TestInteractionRequestEncodingKeepsEssentialACR(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	in := interactionFor(t, h, map[string]string{"claims": acrClaims(`{"essential":true,"values":["urn:gold","urn:silver"]}`)}).Interaction
	text, err := in.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}
	restored, err := server.ParseInteractionRequest(string(text))
	if err != nil {
		t.Fatalf("ParseInteractionRequest: %v", err)
	}
	if want := []string{"urn:gold", "urn:silver"}; !slices.Equal(restored.EssentialACRValues, want) {
		t.Errorf("restored EssentialACRValues = %q, want %q", restored.EssentialACRValues, want)
	}
}

// TestPushAuthorizationRequestRejectsMalformedACRClaim: a malformed
// id_token acr entry is refused rather than read as asking for nothing.
func TestPushAuthorizationRequestRejectsMalformedACRClaim(t *testing.T) {
	for name, entry := range map[string]string{
		"not an object":       `"urn:gold"`,
		"essential not bool":  `{"essential":"yes","value":"urn:gold"}`,
		"value not a string":  `{"essential":true,"value":1}`,
		"empty value":         `{"essential":true,"value":""}`,
		"values not an array": `{"essential":true,"values":"urn:gold"}`,
		"empty values":        `{"essential":true,"values":[]}`,
		"empty member":        `{"essential":true,"values":["urn:gold",""]}`,
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, server.ProfileFAPISecurity, true)
			_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
				HTTP: server.FormRequest{Parameters: plainFormParameters(t, h.clientAssertion(t), map[string]string{"claims": acrClaims(entry)})},
			})
			if code := serverErrorCode(t, err); code != server.ErrorInvalidRequest {
				t.Fatalf("PushAuthorizationRequest(acr %s) error code = %q, want invalid_request", entry, code)
			}
		})
	}
}

// TestCIBAEnforcesEssentialACR: CIBA records an unmet essential acr as a
// failed authentication, so the poll answers access_denied and issues
// nothing; a met one issues tokens as usual.
func TestCIBAEnforcesEssentialACR(t *testing.T) {
	for _, tc := range []struct {
		name    string
		acr     string
		wantErr bool
	}{
		{name: "met", acr: "urn:gold"},
		{name: "not met", acr: "urn:bronze", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := newHarnessWithBackchannel(t)
			params := standardBackchannelParams(t)
			params["claims"] = json.RawMessage(acrClaims(`{"essential":true,"values":["urn:gold"]}`))
			required := beginBackchannel(t, h, params)
			if want := []string{"urn:gold"}; !slices.Equal(required.Interaction.EssentialACRValues, want) {
				t.Errorf("EssentialACRValues = %q, want %q", required.Interaction.EssentialACRValues, want)
			}
			if err := h.server.CompleteBackchannelAuthentication(context.Background(), server.CompleteBackchannelAuthenticationRequest{
				Handle: required.Handle, Result: authorizedWithACR(t, h, tc.acr),
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
			if tc.wantErr {
				if code := serverErrorCode(t, err); code != server.ErrorAccessDenied {
					t.Fatalf("exchange error code = %q, want access_denied", code)
				}
				return
			}
			if err != nil || result.AccessToken.Reveal() == "" {
				t.Fatalf("exchange = %v, want tokens", err)
			}
		})
	}
}

// TestCIBARejectsMalformedACRClaim mirrors the pushed authorization
// request's refusal for the backchannel request.
func TestCIBARejectsMalformedACRClaim(t *testing.T) {
	h, _ := newHarnessWithBackchannel(t)
	params := standardBackchannelParams(t)
	params["claims"] = json.RawMessage(acrClaims(`{"essential":true,"values":"urn:gold"}`))
	action, err := h.server.BeginBackchannelAuthentication(context.Background(), server.BeginBackchannelAuthenticationRequest{
		HTTP: server.FormRequest{Parameters: backchannelFormParams(h.clientAssertion(t), h.backchannelRequestObject(t, params))},
	})
	if err != nil {
		t.Fatalf("BeginBackchannelAuthentication: %v", err)
	}
	local, ok := action.(server.BackchannelAuthenticationLocalError)
	if !ok || local.Error.Code() != server.ErrorInvalidRequest {
		t.Fatalf("action = %#v, want an invalid_request local error", action)
	}
}

package server_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/server"
)

// hintClaims are an ID token's claims as h's server would issue them to
// testClientID for user-1, expired half an hour ago.
func hintClaims(h harness) map[string]any {
	return map[string]any{
		"iss": testIssuer, "sub": "user-1", "aud": string(testClientID),
		"iat": h.now.Add(-time.Hour).Unix(), "exp": h.now.Add(-30 * time.Minute).Unix(),
	}
}

// signHint signs claims as an ES256 ID token with key under kid.
func signHint(t *testing.T, key *ecdsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256, KeyID: kid}, payload)
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

// serverHint is an ID token h's server signed, with change applied to
// hintClaims first.
func serverHint(t *testing.T, h harness, change func(map[string]any)) string {
	t.Helper()
	claims := hintClaims(h)
	if change != nil {
		change(claims)
	}
	return signHint(t, h.serverKey, "as-key-1", claims)
}

// subClaims is a "claims" parameter requesting sub with value at
// location.
func subClaims(location, value string) string {
	return `{"` + location + `":{"sub":{"value":"` + value + `"}}}`
}

// authorizedAs authorizes sub now.
func authorizedAs(t *testing.T, h harness, sub string) server.InteractionResult {
	t.Helper()
	subjectID, err := server.NewSubjectID(sub)
	if err != nil {
		t.Fatal(err)
	}
	subject, err := server.NewAuthenticatedSubject(subjectID)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := server.NewAuthenticationContext(h.now, "", []string{"pwd"})
	if err != nil {
		t.Fatal(err)
	}
	return server.Authorize(subject, auth, server.GrantedAuthorization{Scope: []string{"openid", "accounts"}})
}

// forgetRequiredSubject rewrites every pending interaction's stored
// request without required_subject, as a record written before it
// existed is.
func forgetRequiredSubject(t *testing.T, h harness) {
	t.Helper()
	h.transactions.mu.Lock()
	defer h.transactions.mu.Unlock()
	for handle, pending := range h.transactions.byHandle {
		var record map[string]json.RawMessage
		if err := json.Unmarshal(pending.interaction.Request, &record); err != nil {
			t.Fatal(err)
		}
		if _, ok := record["required_subject"]; !ok {
			t.Fatal("the stored request has no required_subject to forget")
		}
		delete(record, "required_subject")
		raw, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		pending.interaction.Request = raw
		h.transactions.byHandle[handle] = pending
	}
}

// completeAs completes required as sub and returns the redirect's query.
func completeAs(t *testing.T, h harness, required server.InteractionRequired, sub string) map[string]string {
	t.Helper()
	completed, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{Handle: required.Handle, Result: authorizedAs(t, h, sub)})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	redirect, ok := completed.(server.AuthorizationRedirect)
	if !ok {
		t.Fatalf("result = %T, want a redirect", completed)
	}
	dest := redirect.Destination().URL()
	q := dest.Query()
	return map[string]string{"code": q.Get("code"), "error": q.Get("error"), "error_description": q.Get("error_description")}
}

// TestCompleteAuthorizationEnforcesRequiredSubject covers OIDC Core
// §3.1.2.1 and §5.5.1: the end user an id_token_hint or a claims sub
// value names is surfaced as RequiredSubject, and a completion for
// anyone else is login_required with no code; a record written before
// the requirement was kept isn't checked.
func TestCompleteAuthorizationEnforcesRequiredSubject(t *testing.T) {
	for _, tc := range []struct {
		name      string
		extra     func(h harness) map[string]string
		user      string
		legacy    bool
		wantSub   string
		wantError string
	}{
		{name: "no requirement", extra: func(harness) map[string]string { return nil }, user: "user-2"},
		{name: "hint, same user", extra: func(h harness) map[string]string { return map[string]string{"id_token_hint": serverHint(t, h, nil)} }, user: "user-1", wantSub: "user-1"},
		{name: "hint, different user", extra: func(h harness) map[string]string { return map[string]string{"id_token_hint": serverHint(t, h, nil)} }, user: "user-2", wantSub: "user-1", wantError: "login_required"},
		{name: "unexpired hint", extra: func(h harness) map[string]string {
			return map[string]string{"id_token_hint": serverHint(t, h, func(c map[string]any) { c["exp"] = h.now.Add(time.Hour).Unix() })}
		}, user: "user-1", wantSub: "user-1"},
		{name: "hint naming other audiences too", extra: func(h harness) map[string]string {
			return map[string]string{"id_token_hint": serverHint(t, h, func(c map[string]any) {
				c["aud"] = []string{string(testClientID), "other"}
				c["azp"] = string(testClientID)
			})}
		}, user: "user-1", wantSub: "user-1"},
		{name: "id_token sub value, same user", extra: func(harness) map[string]string { return map[string]string{"claims": subClaims("id_token", "user-1")} }, user: "user-1", wantSub: "user-1"},
		{name: "id_token sub value, different user", extra: func(harness) map[string]string { return map[string]string{"claims": subClaims("id_token", "user-1")} }, user: "user-2", wantSub: "user-1", wantError: "login_required"},
		{name: "userinfo sub value, different user", extra: func(harness) map[string]string { return map[string]string{"claims": subClaims("userinfo", "user-1")} }, user: "user-2", wantSub: "user-1", wantError: "login_required"},
		{name: "sub without a value", extra: func(harness) map[string]string {
			return map[string]string{"claims": `{"id_token":{"sub":{"essential":true}}}`}
		}, user: "user-2"},
		{name: "hint and agreeing sub value", extra: func(h harness) map[string]string {
			return map[string]string{"id_token_hint": serverHint(t, h, nil), "claims": `{"id_token":{"sub":{"value":"user-1"}},"userinfo":{"sub":{"value":"user-1"}}}`}
		}, user: "user-2", wantSub: "user-1", wantError: "login_required"},
		{name: "record without the requirement", extra: func(h harness) map[string]string { return map[string]string{"id_token_hint": serverHint(t, h, nil)} }, user: "user-2", legacy: true, wantSub: "user-1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, server.ProfileFAPISecurity, true)
			required := interactionFor(t, h, tc.extra(h))
			if required.Interaction.RequiredSubject != tc.wantSub {
				t.Errorf("RequiredSubject = %q, want %q", required.Interaction.RequiredSubject, tc.wantSub)
			}
			if tc.legacy {
				forgetRequiredSubject(t, h)
			}
			got := completeAs(t, h, required, tc.user)
			if got["error"] != tc.wantError {
				t.Errorf("error = %q (%s), want %q", got["error"], got["error_description"], tc.wantError)
			}
			if (got["code"] != "") != (tc.wantError == "") {
				t.Errorf("code present = %v, want %v", got["code"] != "", tc.wantError == "")
			}
			if tc.wantError == "" {
				return
			}
			if len(h.grants.all()) != 0 {
				t.Error("a code was stored for a refused completion")
			}
			last := h.audit.events[len(h.audit.events)-1]
			if last.Type != server.AuditEventCompleteAuthorization || last.Outcome != server.AuditOutcomeFailure {
				t.Errorf("last audit = %v/%v, want a failed completion", last.Type, last.Outcome)
			}
		})
	}
}

// TestIDTokenHintRoundTrip: an ID token the server actually issued
// names its subject when sent back as a hint.
func TestIDTokenHintRoundTrip(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	code := completeAs(t, h, interactionFor(t, h, nil), "user-1")["code"]
	result, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:       server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
		DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
	})
	if err != nil || !result.HasIDToken {
		t.Fatalf("ExchangeAuthorizationCode = %v (ID token %v), want an ID token", err, result.HasIDToken)
	}
	required := interactionFor(t, h, map[string]string{"id_token_hint": result.IDToken.Reveal()})
	if required.Interaction.RequiredSubject != "user-1" {
		t.Errorf("RequiredSubject = %q, want user-1", required.Interaction.RequiredSubject)
	}
}

// TestIDTokenHintSignedWithPreviousKey: a hint signed with a key the
// server has since rotated away from, but still publishes, is accepted.
func TestIDTokenHintSignedWithPreviousKey(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	hint := serverHint(t, h, nil)
	deps := h.deps
	deps.Keys = &rotatingKeyManager{
		outgoing: &fakeKeyManager{key: h.serverKey, keyID: "as-key-1"},
		newest:   &fakeKeyManager{key: generateKey(t), keyID: "as-key-2"},
	}
	srv, err := server.New(h.cfg, deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	rotated := h
	rotated.server = srv
	if got := interactionFor(t, rotated, map[string]string{"id_token_hint": hint}).Interaction.RequiredSubject; got != "user-1" {
		t.Errorf("RequiredSubject = %q, want user-1", got)
	}
}

// TestPushAuthorizationRequestRejectsUnusableRequiredSubject: a hint
// that isn't an ID token this server issued to the client, and a
// malformed or conflicting sub value, are invalid_request rather than
// ignored.
func TestPushAuthorizationRequestRejectsUnusableRequiredSubject(t *testing.T) {
	for _, tc := range []struct {
		name  string
		extra func(t *testing.T, h harness) map[string]string
	}{
		{"another issuer", hintWith(func(c map[string]any) { c["iss"] = "https://other.example" })},
		{"another client's aud", hintWith(func(c map[string]any) { c["aud"] = "other-client" })},
		{"another client's azp", hintWith(func(c map[string]any) {
			c["aud"] = []string{string(testClientID), "other-client"}
			c["azp"] = "other-client"
		})},
		{"empty sub", hintWith(func(c map[string]any) { c["sub"] = "" })},
		{"forged signature", func(t *testing.T, h harness) map[string]string {
			return map[string]string{"id_token_hint": signHint(t, generateKey(t), "as-key-1", hintClaims(h))}
		}},
		{"unknown kid", func(t *testing.T, h harness) map[string]string {
			return map[string]string{"id_token_hint": signHint(t, h.serverKey, "as-key-9", hintClaims(h))}
		}},
		{"tampered payload", func(t *testing.T, h harness) map[string]string {
			parts := strings.Split(serverHint(t, h, nil), ".")
			other := strings.Split(serverHint(t, h, func(c map[string]any) { c["sub"] = "user-2" }), ".")
			return map[string]string{"id_token_hint": parts[0] + "." + other[1] + "." + parts[2]}
		}},
		{"encrypted", fixed(map[string]string{"id_token_hint": "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0.a.b.c.d"})},
		{"not a JWT", fixed(map[string]string{"id_token_hint": "user-1"})},
		{"hint and sub value disagree", func(t *testing.T, h harness) map[string]string {
			return map[string]string{"id_token_hint": serverHint(t, h, nil), "claims": subClaims("id_token", "user-2")}
		}},
		{"sub values disagree", fixed(map[string]string{"claims": `{"id_token":{"sub":{"value":"user-1"}},"userinfo":{"sub":{"value":"user-2"}}}`})},
		{"sub value not a string", fixed(map[string]string{"claims": `{"id_token":{"sub":{"value":1}}}`})},
		{"empty sub value", fixed(map[string]string{"claims": subClaims("userinfo", "")})},
		{"miscased value member", fixed(map[string]string{"claims": `{"id_token":{"sub":{"Value":"user-1"}}}`})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, server.ProfileFAPISecurity, true)
			_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
				HTTP: server.FormRequest{Parameters: plainFormParameters(t, h.clientAssertion(t), tc.extra(t, h))},
			})
			if code := serverErrorCode(t, err); code != server.ErrorInvalidRequest {
				t.Fatalf("PushAuthorizationRequest error code = %q, want invalid_request", code)
			}
		})
	}
}

func hintWith(change func(map[string]any)) func(*testing.T, harness) map[string]string {
	return func(t *testing.T, h harness) map[string]string {
		return map[string]string{"id_token_hint": serverHint(t, h, change)}
	}
}

func fixed(extra map[string]string) func(*testing.T, harness) map[string]string {
	return func(*testing.T, harness) map[string]string { return extra }
}

// TestIDTokenHintInRequestObject: the hint is honoured in a signed
// request object as well as in plain parameters.
func TestIDTokenHintInRequestObject(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	params := standardAuthParams(t)
	params["id_token_hint"] = jsonRaw(t, serverHint(t, h, nil))
	push, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_assertion", h.clientAssertion(t)),
			formParam("client_assertion_type", clientassertion.AssertionType),
			formParam("request", h.requestObject(t, params)),
		}},
	})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
	action, err := h.server.BeginAuthorization(context.Background(), server.BeginAuthorizationRequest{ClientID: testClientID, RequestURI: push.RequestURI.String()})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	required, ok := action.(server.InteractionRequired)
	if !ok || required.Interaction.RequiredSubject != "user-1" {
		t.Fatalf("action = %#v, want an interaction requiring user-1", action)
	}
}

// TestIDTokenHintRefusedWhenOAuthOnly: a server that issues no ID tokens
// has none to recognise.
func TestIDTokenHintRefusedWhenOAuthOnly(t *testing.T) {
	h := newHarnessOAuthOnly(t)
	_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: plainFormParameters(t, h.clientAssertion(t), map[string]string{
			"scope": "accounts", "id_token_hint": serverHint(t, h, nil),
		})},
	})
	if code := serverErrorCode(t, err); code != server.ErrorInvalidRequest {
		t.Fatalf("PushAuthorizationRequest error code = %q, want invalid_request", code)
	}
}

// TestInteractionRequestEncodingKeepsRequiredSubject: the requirement
// survives the encoding the application stores between instances.
func TestInteractionRequestEncodingKeepsRequiredSubject(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	in := interactionFor(t, h, map[string]string{"claims": subClaims("id_token", "user-1")}).Interaction
	text, err := in.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}
	restored, err := server.ParseInteractionRequest(string(text))
	if err != nil {
		t.Fatalf("ParseInteractionRequest: %v", err)
	}
	if restored.RequiredSubject != "user-1" {
		t.Errorf("restored RequiredSubject = %q, want user-1", restored.RequiredSubject)
	}
}

// TestCIBAEnforcesRequiredSubject: CIBA verifies an id_token_hint the
// same way, surfaces its subject (also on lookup), and records a
// completion for anyone else as a failed authentication, so the poll
// answers access_denied; a claims sub value is honoured alongside a
// login_hint.
func TestCIBAEnforcesRequiredSubject(t *testing.T) {
	for _, tc := range []struct {
		name    string
		hint    bool
		user    string
		wantErr bool
	}{
		{name: "hint, same user", hint: true, user: "user-1"},
		{name: "hint, different user", hint: true, user: "user-2", wantErr: true},
		{name: "sub value, same user", user: "user-1"},
		{name: "sub value, different user", user: "user-2", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := newHarnessWithBackchannel(t)
			params := standardBackchannelParams(t)
			if tc.hint {
				delete(params, "login_hint")
				params["id_token_hint"] = jsonRaw(t, serverHint(t, h, nil))
			} else {
				params["claims"] = json.RawMessage(subClaims("id_token", "user-1"))
			}
			required := beginBackchannel(t, h, params)
			if required.Interaction.RequiredSubject != "user-1" {
				t.Errorf("RequiredSubject = %q, want user-1", required.Interaction.RequiredSubject)
			}
			looked, err := h.server.LookupBackchannelInteraction(context.Background(), required.Handle)
			if err != nil || looked.RequiredSubject != "user-1" {
				t.Errorf("LookupBackchannelInteraction = %q, %v; want user-1", looked.RequiredSubject, err)
			}
			if err := h.server.CompleteBackchannelAuthentication(context.Background(), server.CompleteBackchannelAuthenticationRequest{
				Handle: required.Handle, Result: authorizedAs(t, h, tc.user),
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

// TestCIBARejectsUnusableIDTokenHint: an id_token_hint this server
// didn't issue to the client is invalid_request at the backchannel
// endpoint too.
func TestCIBARejectsUnusableIDTokenHint(t *testing.T) {
	for name, hint := range map[string]func(h harness) string{
		"forged":         func(h harness) string { return signHint(t, generateKey(t), "as-key-1", hintClaims(h)) },
		"another client": func(h harness) string { return serverHint(t, h, func(c map[string]any) { c["aud"] = "other-client" }) },
		"another issuer": func(h harness) string {
			return serverHint(t, h, func(c map[string]any) { c["iss"] = "https://other.example" })
		},
	} {
		t.Run(name, func(t *testing.T) {
			h, _ := newHarnessWithBackchannel(t)
			params := standardBackchannelParams(t)
			delete(params, "login_hint")
			params["id_token_hint"] = jsonRaw(t, hint(h))
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
		})
	}
}

// TestVerifyIDTokenHint: the public wrapper returns the hint's subject
// for an ID token this server issued to the client, expired or not, and
// invalid_request for anything else.
func TestVerifyIDTokenHint(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	ctx := context.Background()
	sub, err := h.server.VerifyIDTokenHint(ctx, serverHint(t, h, nil), testClientID)
	if err != nil || sub != "user-1" {
		t.Fatalf("VerifyIDTokenHint(expired hint) = %q, %v; want user-1", sub, err)
	}
	for name, hint := range map[string]string{
		"empty":          "",
		"not a JWT":      "not-a-jwt",
		"another client": serverHint(t, h, func(c map[string]any) { c["aud"] = "other-client" }),
		"another issuer": serverHint(t, h, func(c map[string]any) { c["iss"] = "https://other.example.com" }),
		"another azp":    serverHint(t, h, func(c map[string]any) { c["azp"] = "other-client" }),
		"forged":         signHint(t, h.key, "as-key-1", hintClaims(h)),
		"tampered":       tamperPayload(t, serverHint(t, h, nil)),
	} {
		t.Run(name, func(t *testing.T) {
			sub, err := h.server.VerifyIDTokenHint(ctx, hint, testClientID)
			if sub != "" {
				t.Errorf("subject = %q, want none", sub)
			}
			if code := serverErrorCode(t, err); code != server.ErrorInvalidRequest {
				t.Errorf("error code = %q, want invalid_request", code)
			}
		})
	}
}

// tamperPayload swaps compact's payload for one naming another subject,
// keeping its signature.
func tamperPayload(t *testing.T, compact string) string {
	t.Helper()
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %q", compact)
	}
	return parts[0] + "." + "eyJzdWIiOiJtYWxsb3J5In0" + "." + parts[2]
}

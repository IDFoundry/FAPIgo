package server_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// beginPaymentInteraction begins an authorization requesting two
// payments, returning what BeginAuthorization gave the application.
func beginPaymentInteraction(t *testing.T) (harness, server.InteractionRequired) {
	t.Helper()
	h := newHarnessWithRAR(t, server.ProfileFAPISecurity, newTestRARRegistry(t), fakeRARPolicy{allow: map[string]bool{"payment": true}}, fakeRARPolicy{allow: map[string]bool{"payment": true}})
	pushResult, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: plainFormParameters(t, h.clientAssertion(t), map[string]string{
			"authorization_details": `[{"type":"payment","actions":["approve"],"amount":"SGD 500.00"},{"type":"payment","actions":["approve"],"amount":"SGD 10.00"}]`,
			"login_hint":            "alice@example.com",
		})},
	})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
	action, err := h.server.BeginAuthorization(context.Background(), server.BeginAuthorizationRequest{RequestURI: pushResult.RequestURI.String(), ClientID: testClientID})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	required, ok := action.(server.InteractionRequired)
	if !ok {
		t.Fatalf("action = %T, want InteractionRequired", action)
	}
	return h, required
}

// TestInteractionRequestRoundTrip covers storing an interaction, as an
// application running several instances does, and completing it from
// the restored copy.
func TestInteractionRequestRoundTrip(t *testing.T) {
	h, required := beginPaymentInteraction(t)

	stored, err := required.Interaction.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}
	if strings.Contains(string(stored), "alice") {
		t.Errorf("encoding %q isn't opaque", stored)
	}
	handleText := required.Handle.String()

	// Another instance: the handle and the interaction, from storage.
	restored, err := server.ParseInteractionRequest(string(stored))
	if err != nil {
		t.Fatalf("ParseInteractionRequest: %v", err)
	}
	if !reflect.DeepEqual(restored, required.Interaction) {
		t.Fatalf("restored %+v, want %+v", restored, required.Interaction)
	}
	handle, err := server.ParseInteractionHandle(handleText)
	if err != nil {
		t.Fatal(err)
	}
	details, err := extension.RARGet(restored.AuthorizationDetails, paymentRARDef)
	if err != nil || len(details) != 2 {
		t.Fatalf("RARGet(restored) = %d details, %v", len(details), err)
	}
	subject, authCtx := rarSubjectAndAuthCtx(t, h.now)
	result, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
		Handle: handle,
		Result: server.Authorize(subject, authCtx, server.GrantedAuthorization{
			Scope: restored.Scope, AuthorizationDetails: []json.RawMessage{mustMarshal(t, details[1].Fields)},
		}),
	})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	if _, ok := result.(server.AuthorizationRedirect); !ok {
		t.Fatalf("result = %T, want AuthorizationRedirect", result)
	}
}

// TestTamperedInteractionCantWidenGrant covers the doc comment's claim:
// a stored copy changed to show a payment that was never requested
// can't get it granted.
func TestTamperedInteractionCantWidenGrant(t *testing.T) {
	h, required := beginPaymentInteraction(t)
	tampered := required.Interaction
	if err := json.Unmarshal([]byte(`[{"type":"payment","actions":["approve"],"amount":"SGD 99999.00"}]`), &tampered.AuthorizationDetails); err != nil {
		t.Fatal(err)
	}
	details, err := extension.RARGet(tampered.AuthorizationDetails, paymentRARDef)
	if err != nil || len(details) != 1 {
		t.Fatalf("RARGet = %v, %v", details, err)
	}
	subject, authCtx := rarSubjectAndAuthCtx(t, h.now)
	result, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
		Handle: required.Handle,
		Result: server.Authorize(subject, authCtx, server.GrantedAuthorization{
			Scope: tampered.Scope, AuthorizationDetails: []json.RawMessage{mustMarshal(t, details[0].Fields)},
		}),
	})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	if _, refused := result.(server.AuthorizationLocalError); !refused {
		t.Fatalf("result = %T, want the grant refused (AuthorizationLocalError)", result)
	}
}

func TestParseInteractionRequestRejects(t *testing.T) {
	enc := func(s string) string { return "v1." + base64.RawURLEncoding.EncodeToString([]byte(s)) }
	for name, text := range map[string]string{
		"empty":           "",
		"unknown version": "v9." + base64.RawURLEncoding.EncodeToString([]byte(`{"client_id":"c"}`)),
		"not base64":      "v1.!!!",
		"not JSON":        enc("x"),
		"unknown member":  enc(`{"client_id":"c","authorization_details":[],"extensions":{},"z":1}`),
		"no client":       enc(`{"authorization_details":[],"extensions":{}}`),
		"untyped detail":  enc(`{"client_id":"c","authorization_details":[{"amount":"1"}],"extensions":{}}`),
		"bad logo URL":    enc(`{"client_id":"c","logo_uri":"javascript:alert(1)","authorization_details":[],"extensions":{}}`),
		"too long":        "v1." + strings.Repeat("A", 64<<10),
	} {
		if _, err := server.ParseInteractionRequest(text); err == nil {
			t.Errorf("ParseInteractionRequest(%s) = nil error, want error", name)
		}
	}
	var r server.InteractionRequest
	if err := r.UnmarshalText([]byte("v1.!!!")); err == nil {
		t.Error("UnmarshalText(malformed) = nil error, want error")
	}
	if _, err := (server.InteractionRequest{}).MarshalText(); err == nil {
		t.Error("MarshalText(zero) = nil error, want error")
	}
}

// TestInteractionRequestFullRoundTrip covers every field, restored
// through UnmarshalText as part of the application's own JSON record.
func TestInteractionRequestFullRoundTrip(t *testing.T) {
	logo, err := fapi.ParseEndpointURL("https://rp.example/logo.png")
	if err != nil {
		t.Fatal(err)
	}
	policy, _ := fapi.ParseEndpointURL("https://rp.example/privacy")
	tos, _ := fapi.ParseEndpointURL("https://rp.example/terms")
	var extensions extension.Values
	def := extension.Definition[string]{Name: "issuer_state", Cardinality: extension.Single, AllowedSources: extension.SourcePlainParameter, MaxBytes: 64}
	if err := extension.Set(&extensions, def, "state-1"); err != nil {
		t.Fatal(err)
	}
	in := server.InteractionRequest{
		ClientID: testClientID, Scope: []string{"openid", "accounts"},
		Hints:           server.AuthenticationHints{LoginHint: "alice"},
		ClientDisplay:   storage.ClientDisplay{Name: "RP", LogoURI: logo, PolicyURI: policy, TermsOfServiceURI: tos},
		RequestedClaims: server.RequestedClaims{IDToken: []string{"email"}, UserInfo: []string{"name"}},
		Extensions:      extensions,
	}
	type session struct {
		Interaction server.InteractionRequest `json:"interaction"`
	}
	raw, err := json.Marshal(session{Interaction: in})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var out session
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(out.Interaction, in) {
		t.Errorf("restored %+v, want %+v", out.Interaction, in)
	}
	if got, ok := extension.Get(out.Interaction.Extensions, def); !ok || got != "state-1" {
		t.Errorf("restored extension = %q, %v", got, ok)
	}
}

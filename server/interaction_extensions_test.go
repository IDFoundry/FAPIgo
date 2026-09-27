package server_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// issuerStateDef stands in for OID4VCI's issuer_state: accepted from
// either source, and deliberately not ReturnInTokenClaims — reading it
// at the interaction step mustn't depend on token-claim opt-in.
var issuerStateDef = extension.Definition[string]{
	Name: "issuer_state", Cardinality: extension.Single,
	AllowedSources: extension.SourcePlainParameter | extension.SourceRequestObject,
	MaxBytes:       256,
}

type issuanceRef struct {
	Ref string `json:"ref"`
}

// issuanceDef is a structured, request-object-only extension.
var issuanceDef = extension.Definition[issuanceRef]{
	Name: "x_issuance", Cardinality: extension.Single,
	AllowedSources: extension.SourceRequestObject,
	MaxBytes:       256,
}

func newInteractionExtensionsHarness(t *testing.T) harness {
	t.Helper()
	registry, err := extension.NewRegistry(issuerStateDef, issuanceDef)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	return newHarnessWithExtensions(t, server.ProfileFAPISecurity, registry)
}

func beginWith(t *testing.T, h harness, form []server.FormParameter) server.AuthorizationAction {
	t.Helper()
	pushResult, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: form},
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
	return action
}

func interactionOf(t *testing.T, action server.AuthorizationAction) server.InteractionRequest {
	t.Helper()
	required, ok := action.(server.InteractionRequired)
	if !ok {
		t.Fatalf("action = %T, want server.InteractionRequired", action)
	}
	return required.Interaction
}

func requestObjectForm(t *testing.T, h harness) []server.FormParameter {
	t.Helper()
	params := standardAuthParams(t)
	params["issuer_state"] = jsonRaw(t, "state-from-object")
	params["x_issuance"] = jsonRaw(t, issuanceRef{Ref: "passport-42"})
	return []server.FormParameter{
		formParam("client_assertion", h.clientAssertion(t)),
		formParam("client_assertion_type", clientassertion.AssertionType),
		formParam("request", h.requestObject(t, params)),
	}
}

func TestInteractionRequestExposesPlainParameterExtension(t *testing.T) {
	h := newInteractionExtensionsHarness(t)
	interaction := interactionOf(t, beginWith(t, h, plainFormParameters(t, h.clientAssertion(t), map[string]string{"issuer_state": "state-plain"})))

	got, ok := extension.Get(interaction.Extensions, issuerStateDef)
	if !ok || got != "state-plain" {
		t.Fatalf("issuer_state = %q (present %v), want %q", got, ok, "state-plain")
	}
	if _, ok := extension.Get(interaction.Extensions, issuanceDef); ok {
		t.Fatal("x_issuance present, but the request didn't carry it")
	}
}

func TestInteractionRequestExposesRequestObjectExtensions(t *testing.T) {
	h := newInteractionExtensionsHarness(t)
	interaction := interactionOf(t, beginWith(t, h, requestObjectForm(t, h)))

	if got, ok := extension.Get(interaction.Extensions, issuerStateDef); !ok || got != "state-from-object" {
		t.Fatalf("issuer_state = %q (present %v), want %q", got, ok, "state-from-object")
	}
	if got, ok := extension.Get(interaction.Extensions, issuanceDef); !ok || got.Ref != "passport-42" {
		t.Fatalf("x_issuance = %+v (present %v), want ref passport-42", got, ok)
	}
}

// rewriteStoredRequests edits every stored pushed request's opaque
// record, as JSON.
func (f *fakeTransactionStore) rewriteStoredRequests(t *testing.T, edit func(map[string]any)) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	for ref, record := range f.byReference {
		var decoded map[string]any
		if err := json.Unmarshal(record.Request, &decoded); err != nil {
			t.Fatalf("decode stored request: %v", err)
		}
		edit(decoded)
		raw, err := json.Marshal(decoded)
		if err != nil {
			t.Fatalf("encode stored request: %v", err)
		}
		record.Request = raw
		f.byReference[ref] = record
	}
}

// TestInteractionRequestToleratesRecordWithoutExtensionSource covers a
// request pushed before the source was recorded and begun after an
// upgrade: it proceeds, just without extension values.
func TestInteractionRequestToleratesRecordWithoutExtensionSource(t *testing.T) {
	h := newInteractionExtensionsHarness(t)
	pushResult, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: plainFormParameters(t, h.clientAssertion(t), map[string]string{"issuer_state": "state-plain"})},
	})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
	h.transactions.rewriteStoredRequests(t, func(r map[string]any) { delete(r, "extension_source") })

	action, err := h.server.BeginAuthorization(context.Background(), server.BeginAuthorizationRequest{
		RequestURI: pushResult.RequestURI.String(), ClientID: testClientID,
	})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	if _, ok := extension.Get(interactionOf(t, action).Extensions, issuerStateDef); ok {
		t.Fatal("issuer_state present, want no extension values for a record without a source")
	}
}

// TestInteractionRequestFailsClosedWhenStoredExtensionsNoLongerValidate
// covers values validated at PAR that don't validate on read-back — here
// a request-object-only value recorded as a plain parameter. The consent
// step must not proceed on a partial picture of the request.
func TestInteractionRequestFailsClosedWhenStoredExtensionsNoLongerValidate(t *testing.T) {
	h := newInteractionExtensionsHarness(t)
	pushResult, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: requestObjectForm(t, h)},
	})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
	h.transactions.rewriteStoredRequests(t, func(r map[string]any) { r["extension_source"] = float64(extension.SourcePlainParameter) })

	action, err := h.server.BeginAuthorization(context.Background(), server.BeginAuthorizationRequest{
		RequestURI: pushResult.RequestURI.String(), ClientID: testClientID,
	})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	local, ok := action.(server.LocalErrorResponse)
	if !ok {
		t.Fatalf("action = %T, want server.LocalErrorResponse", action)
	}
	if local.Error.Code() != server.ErrorServerError {
		t.Fatalf("error code = %q, want %q", local.Error.Code(), server.ErrorServerError)
	}
}

func TestBackchannelInteractionRequestExposesExtensions(t *testing.T) {
	registry, err := extension.NewRegistry(issuerStateDef, issuanceDef)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	h := newHarnessWithBackchannelConfig(t, memstore.NewBackchannelAuthenticationStore(), func(c *server.Config) { c.Extensions = registry })
	params := standardBackchannelParams(t)
	params["issuer_state"] = jsonRaw(t, "ciba-state")
	params["x_issuance"] = jsonRaw(t, issuanceRef{Ref: "passport-7"})

	interaction := beginBackchannel(t, h, params).Interaction
	if got, ok := extension.Get(interaction.Extensions, issuerStateDef); !ok || got != "ciba-state" {
		t.Fatalf("issuer_state = %q (present %v), want %q", got, ok, "ciba-state")
	}
	if got, ok := extension.Get(interaction.Extensions, issuanceDef); !ok || got.Ref != "passport-7" {
		t.Fatalf("x_issuance = %+v (present %v), want ref passport-7", got, ok)
	}
}

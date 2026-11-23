package server_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/internal/rendertest"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// The Sensitive extension values below are each refused by a decoder
// whose error quotes them.
const (
	sensitiveDOBLiteral = "19900102-PRIVATE"
	sensitivePINLiteral = "98765432109876"
	sensitiveIPLiteral  = "10.20.30.400.secret"
)

var (
	sensitiveDOBDef = extension.Definition[time.Time]{
		Sensitivity: extension.Sensitive, Name: "x_dob", Cardinality: extension.Single,
		AllowedSources: extension.SourcePlainParameter, MaxBytes: 64,
	}
	sensitivePINDef = extension.Definition[int32]{
		Sensitivity: extension.Sensitive, Name: "x_pin", Cardinality: extension.Single,
		AllowedSources: extension.SourceRequestObject, MaxBytes: 64,
	}
	sensitiveIPDef = extension.Definition[netip.Addr]{
		Sensitivity: extension.Sensitive, Name: "x_ip", Cardinality: extension.Single,
		AllowedSources: extension.SourceRequestObject, MaxBytes: 64,
	}
)

func sensitiveRegistry(t *testing.T) *extension.Registry {
	t.Helper()
	registry, err := extension.NewRegistry(sensitiveDOBDef, sensitivePINDef, sensitiveIPDef)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	return registry
}

// checkSensitiveRefusal checks err refuses a request for a Sensitive
// parameter's value as it refused any invalid extension value, with
// code and status unchanged, and that its text, meant for logs, names
// the parameter but quotes nothing of the value, nor does any other
// rendering of it, while errors.Is still finds ErrMalformedValue.
func checkSensitiveRefusal(t *testing.T, err error, code server.ErrorCode, param, literal string) {
	t.Helper()
	var serr *server.Error
	if !errors.As(err, &serr) {
		t.Fatalf("err = %v, want a *server.Error", err)
	}
	if serr.Code() != code || serr.HTTPStatus() != 400 || serr.PublicDescription() != "request contains an invalid parameter" {
		t.Errorf("refusal = %s %d %q, want %s 400 and the same description as before", serr.Code(), serr.HTTPStatus(), serr.PublicDescription(), code)
	}
	if text := err.Error(); strings.Contains(text, literal) || !strings.Contains(text, param) {
		t.Errorf("Error() = %q: want %s named and %q nowhere", text, param, literal)
	}
	if errors.As(err, new(*json.UnmarshalTypeError)) || errors.As(err, new(*time.ParseError)) {
		t.Error("the refusal hands out the decoder's error, which quotes the value")
	}
	if !errors.Is(err, extension.ErrMalformedValue) {
		t.Error("errors.Is doesn't find ErrMalformedValue in the refusal")
	}
	rendertest.Check(t, err, []string{literal})
}

// TestSensitiveExtensionRefusalAtPARQuotesNoValue sends a Sensitive
// value its decoder refuses, at the pushed authorization request, as a
// plain parameter and inside a request object.
func TestSensitiveExtensionRefusalAtPARQuotesNoValue(t *testing.T) {
	h := newHarnessWithExtensions(t, server.ProfileFAPISecurity, sensitiveRegistry(t))

	plain := plainFormParameters(t, h.clientAssertion(t), map[string]string{"x_dob": sensitiveDOBLiteral})
	_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{HTTP: server.FormRequest{Parameters: plain}})
	checkSensitiveRefusal(t, err, server.ErrorInvalidRequest, "x_dob", sensitiveDOBLiteral)

	params := standardAuthParams(t)
	params["x_pin"] = json.RawMessage(sensitivePINLiteral)
	object := []server.FormParameter{
		formParam("client_assertion", h.clientAssertion(t)),
		formParam("client_assertion_type", clientassertion.AssertionType),
		formParam("request", h.requestObject(t, params)),
	}
	_, err = h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{HTTP: server.FormRequest{Parameters: object}})
	checkSensitiveRefusal(t, err, server.ErrorInvalidRequestObject, "x_pin", sensitivePINLiteral)
}

// TestSensitiveExtensionRefusalAtCIBAQuotesNoValue sends a Sensitive
// value its decoder refuses in a backchannel authentication request.
func TestSensitiveExtensionRefusalAtCIBAQuotesNoValue(t *testing.T) {
	registry := sensitiveRegistry(t)
	h := newHarnessWithBackchannelConfig(t, memstore.NewBackchannelAuthenticationStore(), func(c *server.Config) { c.Extensions = registry })

	params := standardBackchannelParams(t)
	params["x_ip"] = jsonRaw(t, sensitiveIPLiteral)
	action, err := h.server.BeginBackchannelAuthentication(context.Background(), server.BeginBackchannelAuthenticationRequest{
		HTTP: server.FormRequest{Parameters: backchannelFormParams(h.clientAssertion(t), h.backchannelRequestObject(t, params))},
	})
	if err != nil {
		t.Fatalf("BeginBackchannelAuthentication: %v", err)
	}
	refused, ok := action.(server.BackchannelAuthenticationLocalError)
	if !ok {
		t.Fatalf("action = %T, want a BackchannelAuthenticationLocalError", action)
	}
	checkSensitiveRefusal(t, refused.Error, server.ErrorInvalidRequest, "x_ip", sensitiveIPLiteral)
}

// TestSensitiveExtensionReparseQuotesNoValue covers the read-back of a
// stored request whose Sensitive value no longer validates: the
// interaction fails closed, and its error's text quotes nothing of the
// value either.
func TestSensitiveExtensionReparseQuotesNoValue(t *testing.T) {
	h := newHarnessWithExtensions(t, server.ProfileFAPISecurity, sensitiveRegistry(t))
	params := standardAuthParams(t)
	params["x_pin"] = json.RawMessage(`1234`)
	pushResult, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{HTTP: server.FormRequest{Parameters: []server.FormParameter{
		formParam("client_assertion", h.clientAssertion(t)),
		formParam("client_assertion_type", clientassertion.AssertionType),
		formParam("request", h.requestObject(t, params)),
	}}})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
	h.transactions.rewriteStoredRequests(t, func(r map[string]any) {
		r["parameters"].(map[string]any)["x_pin"] = json.Number(sensitivePINLiteral)
	})

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
	if text := local.Error.Error(); local.Error.Code() != server.ErrorServerError || strings.Contains(text, sensitivePINLiteral) || !strings.Contains(text, "x_pin") {
		t.Errorf("refusal = %s %q: want server_error, naming x_pin and quoting nothing of its value", local.Error.Code(), text)
	}
	if !errors.Is(local.Error, extension.ErrMalformedValue) {
		t.Error("errors.Is doesn't find ErrMalformedValue in the refusal")
	}
	rendertest.Check(t, local.Error, []string{sensitivePINLiteral})
}

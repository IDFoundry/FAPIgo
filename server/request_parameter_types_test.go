package server_test

import (
	"encoding/json"
	"testing"

	"github.com/idfoundry/fapigo/server"
)

// wrongJSONTypes are values of every JSON type but a string, keyed by a
// name for the subtest.
var wrongJSONTypes = map[string]json.RawMessage{
	"number": json.RawMessage(`12345`),
	"object": json.RawMessage(`{"s":"x"}`),
	"array":  json.RawMessage(`["x"]`),
	"null":   json.RawMessage(`null`),
	"bool":   json.RawMessage(`true`),
}

// wrongTypesFor is wrongJSONTypes less the types in accepted.
func wrongTypesFor(accepted ...string) map[string]json.RawMessage {
	out := make(map[string]json.RawMessage, len(wrongJSONTypes))
	for name, v := range wrongJSONTypes {
		out[name] = v
	}
	for _, name := range accepted {
		delete(out, name)
	}
	return out
}

// TestRequestObjectCoreParameterTypes: a signed request object's core
// parameter whose JSON type isn't the one it's defined with — a
// dpop_jkt array, a numeric nonce, an object state — is refused at PAR
// with invalid_request_object, not accepted and then read as absent,
// which would drop the binding, replay or CSRF protection the client
// asked for.
func TestRequestObjectCoreParameterTypes(t *testing.T) {
	cases := map[string]map[string]json.RawMessage{
		"response_type": wrongTypesFor(), "redirect_uri": wrongTypesFor(), "scope": wrongTypesFor(),
		"state": wrongTypesFor(), "nonce": wrongTypesFor(), "code_challenge": wrongTypesFor(),
		"code_challenge_method": wrongTypesFor(), "response_mode": wrongTypesFor(),
		"prompt": wrongTypesFor(), "acr_values": wrongTypesFor(), "login_hint": wrongTypesFor(),
		"id_token_hint": wrongTypesFor(), "dpop_jkt": wrongTypesFor(),
		"max_age": wrongTypesFor("number"), "claims": wrongTypesFor("object"),
	}
	cases["dpop_jkt"]["empty string"] = json.RawMessage(`""`)
	for name, values := range cases {
		for kind, value := range values {
			t.Run(name+"/"+kind, func(t *testing.T) {
				h := newHarness(t, server.ProfileFAPISecurity, true)
				params := standardAuthParams(t)
				params[name] = value
				requireServerErrorCode(t, pushRequestObject(t, h, h.requestObject(t, params)), server.ErrorInvalidRequestObject)
			})
		}
	}
}

// TestRequestObjectCoreParameterTypesAccepted: the types each core
// parameter is defined with are still accepted — max_age as a number or
// a numeric string, claims as an object or a string holding one.
func TestRequestObjectCoreParameterTypesAccepted(t *testing.T) {
	cases := map[string]json.RawMessage{
		"max_age number":   json.RawMessage(`300`),
		"max_age string":   json.RawMessage(`"300"`),
		"claims object":    json.RawMessage(`{"id_token":{"acr":null}}`),
		"claims string":    jsonRawString(`{"id_token":{"acr":null}}`),
		"nonce":            json.RawMessage(`"n-1"`),
		"login_hint":       json.RawMessage(`"user-1"`),
		"ui_locales other": json.RawMessage(`5`),
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, server.ProfileFAPISecurity, true)
			params := standardAuthParams(t)
			params[parameterOf(name)] = value
			if err := pushRequestObject(t, h, h.requestObject(t, params)); err != nil {
				t.Fatalf("PAR: %v", err)
			}
		})
	}
}

// TestBackchannelRequestCoreParameterTypes is
// TestRequestObjectCoreParameterTypes for a CIBA request, refused with
// invalid_request (CIBA Core §13 has no invalid_request_object).
func TestBackchannelRequestCoreParameterTypes(t *testing.T) {
	cases := map[string]map[string]json.RawMessage{
		"scope": wrongTypesFor(), "login_hint": wrongTypesFor(), "acr_values": wrongTypesFor(),
		"binding_message": wrongTypesFor(), "client_notification_token": wrongTypesFor(),
		"dpop_jkt": wrongTypesFor(), "requested_expiry": wrongTypesFor("number"),
		"claims": wrongTypesFor("object"),
	}
	cases["dpop_jkt"]["empty string"] = json.RawMessage(`""`)
	for name, values := range cases {
		for kind, value := range values {
			t.Run(name+"/"+kind, func(t *testing.T) {
				h, _ := newHarnessWithBackchannel(t)
				params := standardBackchannelParams(t)
				params[name] = value
				requireBackchannelErrorCode(t, h, h.backchannelRequestObject(t, params), server.ErrorInvalidRequest)
			})
		}
	}
}

// parameterOf is a TestRequestObjectCoreParameterTypesAccepted case's
// parameter: its name up to the first space.
func parameterOf(name string) string {
	for i := range len(name) {
		if name[i] == ' ' {
			return name[:i]
		}
	}
	return name
}

func jsonRawString(s string) json.RawMessage {
	b, _ := json.Marshal(s) // marshaling a string cannot fail
	return b
}

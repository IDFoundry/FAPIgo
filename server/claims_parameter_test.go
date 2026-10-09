package server_test

import (
	"context"
	"testing"

	"github.com/idfoundry/fapigo/server"
)

// TestMalformedClaimsParameterIsRefused: a claims parameter that isn't a
// JSON object is invalid_request at PAR and at the backchannel
// authentication endpoint, rather than read as no claims at all.
func TestMalformedClaimsParameterIsRefused(t *testing.T) {
	for name, claims := range map[string]string{
		"not JSON": `{"id_token":`,
		// A case variant of a member: its members are case-sensitive,
		// so it's refused rather than silently honoured or ignored.
		"ID_TOKEN":  `{"ID_TOKEN":{"acr":{"essential":true,"values":["gold"]}}}`,
		"Essential": `{"id_token":{"acr":{"Essential":true,"values":["gold"]}}}`,
	} {
		t.Run("PAR "+name, func(t *testing.T) {
			h := newHarness(t, server.ProfileFAPISecurity, true)
			_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
				HTTP: server.FormRequest{Parameters: plainFormParameters(t, h.clientAssertion(t), map[string]string{"claims": claims})},
			})
			if serverErrorCode(t, err) != server.ErrorInvalidRequest {
				t.Fatalf("PAR with claims %s: %v, want invalid_request", claims, err)
			}
		})
	}
	t.Run("CIBA", func(t *testing.T) {
		h, _ := newHarnessWithBackchannel(t)
		params := standardBackchannelParams(t)
		params["claims"] = jsonRaw(t, []string{"email"})
		action, err := h.server.BeginBackchannelAuthentication(context.Background(), server.BeginBackchannelAuthenticationRequest{
			HTTP: server.FormRequest{Parameters: backchannelFormParams(h.clientAssertion(t), h.backchannelRequestObject(t, params))},
		})
		if err != nil {
			t.Fatalf("BeginBackchannelAuthentication: %v", err)
		}
		localErr, ok := action.(server.BackchannelAuthenticationLocalError)
		if !ok || localErr.Error.Code() != server.ErrorInvalidRequest {
			t.Fatalf("action = %#v, want invalid_request", action)
		}
	})
}

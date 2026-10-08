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
	t.Run("PAR", func(t *testing.T) {
		h := newHarness(t, server.ProfileFAPISecurity, true)
		_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
			HTTP: server.FormRequest{Parameters: plainFormParameters(t, h.clientAssertion(t), map[string]string{"claims": `{"id_token":`})},
		})
		if serverErrorCode(t, err) != server.ErrorInvalidRequest {
			t.Fatalf("PAR with a malformed claims parameter: %v, want invalid_request", err)
		}
	})
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

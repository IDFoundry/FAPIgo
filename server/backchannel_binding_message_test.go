package server_test

import (
	"context"
	"testing"

	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// TestRequireBindingMessage: FAPI-CIBA §5.2.2 — with
// Config.RequireBindingMessage, a request without binding_message is
// refused with invalid_request before it's acknowledged; one with it,
// and any request without the setting, is accepted.
func TestRequireBindingMessage(t *testing.T) {
	for name, tc := range map[string]struct {
		require, withMessage bool
		wantRefused          bool
	}{
		"required, missing": {true, false, true},
		"required, present": {true, true, false},
		"default, missing":  {false, false, false},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarnessWithBackchannelConfig(t, memstore.NewBackchannelAuthenticationStore(), func(c *server.Config) { c.RequireBindingMessage = tc.require })
			params := standardBackchannelParams(t)
			if tc.withMessage {
				params["binding_message"] = jsonRaw(t, "Order 1042")
			} else {
				delete(params, "binding_message")
			}
			action, err := h.server.BeginBackchannelAuthentication(context.Background(), server.BeginBackchannelAuthenticationRequest{
				HTTP: server.FormRequest{Parameters: backchannelFormParams(h.clientAssertion(t), h.backchannelRequestObject(t, params))},
			})
			if err != nil {
				t.Fatalf("BeginBackchannelAuthentication: %v", err)
			}
			assertBindingMessageOutcome(t, action, tc.wantRefused)
		})
	}
}

func assertBindingMessageOutcome(t *testing.T, action server.BackchannelAuthenticationAction, wantRefused bool) {
	t.Helper()
	le, refused := action.(server.BackchannelAuthenticationLocalError)
	if refused != wantRefused {
		t.Fatalf("action = %T, want refused %v", action, wantRefused)
	}
	if refused && le.Error.Code() != server.ErrorInvalidRequest {
		t.Fatalf("error = %v, want invalid_request", le.Error.Code())
	}
}

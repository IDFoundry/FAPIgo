package server_test

import (
	"context"
	"testing"

	"github.com/idfoundry/fapigo/server"
)

// TestInvalidDPoPProofAtPARAndCIBA covers RFC 9449 §5's
// invalid_dpop_proof for a single proof that fails verification, at the
// pushed authorization request and backchannel authentication
// endpoints (the token endpoint's own is covered with replay).
func TestInvalidDPoPProofAtPARAndCIBA(t *testing.T) {
	t.Run("PAR", func(t *testing.T) {
		h := newHarness(t, server.ProfileFAPISecurity, true)
		_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
			HTTP:       server.FormRequest{Parameters: plainFormParameters(t, h.clientAssertion(t), nil)},
			DPoPProofs: []string{"not-a-dpop-proof"},
		})
		if code := serverErrorCode(t, err); code != server.ErrorInvalidDPoPProof {
			t.Errorf("error code = %q, want %q", code, server.ErrorInvalidDPoPProof)
		}
	})
	t.Run("CIBA", func(t *testing.T) {
		h, _ := newHarnessWithBackchannel(t)
		action, err := h.server.BeginBackchannelAuthentication(context.Background(), server.BeginBackchannelAuthenticationRequest{
			HTTP:       server.FormRequest{Parameters: backchannelFormParams(h.clientAssertion(t), h.backchannelRequestObject(t, standardBackchannelParams(t)))},
			DPoPProofs: []string{"not-a-dpop-proof"},
		})
		if err != nil {
			t.Fatalf("BeginBackchannelAuthentication: %v", err)
		}
		localErr, ok := action.(server.BackchannelAuthenticationLocalError)
		if !ok || localErr.Error.Code() != server.ErrorInvalidDPoPProof {
			t.Errorf("action = %+v, want invalid_dpop_proof", action)
		}
	})
}

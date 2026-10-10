package server_test

import (
	"context"
	"testing"

	"github.com/idfoundry/fapigo/server"
)

// zeroAuthResult authorizes user-1 with a zero AuthenticationContext{},
// one that bypassed NewAuthenticationContext.
func zeroAuthResult(t *testing.T) server.InteractionResult {
	t.Helper()
	subjectID, err := server.NewSubjectID("user-1")
	if err != nil {
		t.Fatal(err)
	}
	subject, err := server.NewAuthenticatedSubject(subjectID)
	if err != nil {
		t.Fatal(err)
	}
	return server.Authorize(subject, server.AuthenticationContext{}, server.GrantedAuthorization{Scope: []string{"openid", "accounts"}})
}

// TestCompleteAuthorizationRefusesZeroAuthenticationContext: an
// authorization without an authentication time is a server_error, not a
// code whose ID token lacks auth_time.
func TestCompleteAuthorizationRefusesZeroAuthenticationContext(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	handle := interactionFor(t, h, map[string]string{}).Handle
	result, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{Handle: handle, Result: zeroAuthResult(t)})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	local, ok := result.(server.AuthorizationLocalError)
	if !ok {
		t.Fatalf("result = %T, want server.AuthorizationLocalError", result)
	}
	if local.Error.Code() != server.ErrorServerError {
		t.Fatalf("Code = %q, want server_error", local.Error.Code())
	}
}

// TestCompleteBackchannelAuthenticationRefusesZeroAuthenticationContext
// is CIBA's counterpart.
func TestCompleteBackchannelAuthenticationRefusesZeroAuthenticationContext(t *testing.T) {
	h, _ := newHarnessWithBackchannel(t)
	required := beginBackchannel(t, h, standardBackchannelParams(t))
	err := h.server.CompleteBackchannelAuthentication(context.Background(), server.CompleteBackchannelAuthenticationRequest{
		Handle: required.Handle, Result: zeroAuthResult(t),
	})
	if serverErrorCode(t, err) != server.ErrorServerError {
		t.Fatalf("CompleteBackchannelAuthentication = %v, want server_error", err)
	}
}

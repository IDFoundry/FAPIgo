package server_test

import (
	"context"
	"testing"

	"github.com/idfoundry/fapigo/server"
)

// TestCompleteBackchannelAuthenticationRefusesGrantWithoutOpenID: a CIBA
// request carries "openid" and its token response must carry an ID
// token (CIBA Core §10.1.1), so an approval granting a scope without
// "openid" is refused, as a scope exceeding the request's is, and the
// request stays pending for a corrected decision.
func TestCompleteBackchannelAuthenticationRefusesGrantWithoutOpenID(t *testing.T) {
	h, _ := newHarnessWithBackchannel(t)
	required := beginBackchannel(t, h, standardBackchannelParams(t))
	subject, err := server.NewSubjectID("user-1")
	if err != nil {
		t.Fatal(err)
	}
	authenticated, err := server.NewAuthenticatedSubject(subject)
	if err != nil {
		t.Fatal(err)
	}
	authCtx, err := server.NewAuthenticationContext(h.now, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	complete := func(scope ...string) error {
		return h.server.CompleteBackchannelAuthentication(context.Background(), server.CompleteBackchannelAuthenticationRequest{
			Handle: required.Handle,
			Result: server.Authorize(authenticated, authCtx, server.GrantedAuthorization{Scope: scope}),
		})
	}
	if code := serverErrorCode(t, complete("accounts")); code != server.ErrorInvalidRequest {
		t.Fatalf("CompleteBackchannelAuthentication(without openid) code = %q, want invalid_request", code)
	}
	if err := complete("openid", "accounts"); err != nil {
		t.Fatalf("CompleteBackchannelAuthentication(with openid) after the refusal: %v", err)
	}
}

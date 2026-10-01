package server_test

import (
	"context"
	"errors"
	"testing"

	"github.com/idfoundry/fapigo/server"
)

// TestClientIDAloneAsksForTheRightCredential covers a request carrying
// only a client_id. For a client registered for private_key_jwt that is
// simply no client authentication — not a request for a client
// certificate it was never meant to have. A client registered for
// certificate authentication is still told it needs one.
func TestClientIDAloneAsksForTheRightCredential(t *testing.T) {
	cases := map[string]struct {
		h    harness
		want string
	}{
		"private_key_jwt client": {newHarness(t, server.ProfileFAPISecurity, true), "client authentication is required"},
	}
	mtlsHarness, _ := newHarnessWithClientAuthSelfSignedTLS(t)
	cases["self_signed_tls_client_auth client"] = struct {
		h    harness
		want string
	}{mtlsHarness, "a client certificate is required for client authentication"}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := tc.h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
				HTTP: server.FormRequest{Parameters: certFormParameters(nil)},
			})
			var serr *server.Error
			if !errors.As(err, &serr) || serr.Code() != server.ErrorInvalidClient {
				t.Fatalf("PushAuthorizationRequest(client_id only) = %v, want invalid_client", err)
			}
			if got := serr.PublicDescription(); got != tc.want {
				t.Errorf("description = %q, want %q", got, tc.want)
			}
		})
	}
}

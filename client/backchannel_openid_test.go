package client_test

import (
	"context"
	"testing"

	"github.com/idfoundry/fapigo/client"
)

// TestBeginBackchannelAuthenticationRequiresOpenID: CIBA is an OpenID
// Connect flow, and CIBA Core §7.1 says the scope MUST include openid,
// so a request without it is refused before anything is sent.
func TestBeginBackchannelAuthenticationRequiresOpenID(t *testing.T) {
	c, as, _ := newTestClientWithCIBA(t)
	_, err := c.BeginBackchannelAuthentication(context.Background(), client.BeginBackchannelAuthenticationRequest{
		Scope: []string{"accounts"}, LoginHint: "user@example.com",
	})
	if code := clientErrorCode(t, err); code != client.ErrorInvalidRequest {
		t.Fatalf("error code = %q, want %q", code, client.ErrorInvalidRequest)
	}
	if as.lastBCForm != nil {
		t.Errorf("a request without openid reached the backchannel authentication endpoint")
	}
}

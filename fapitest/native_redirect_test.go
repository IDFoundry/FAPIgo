package fapitest_test

import (
	"context"
	"testing"

	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/fapitest"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// TestNativeLoopbackRedirectPortEndToEnd covers a desktop app's loopback
// redirect over real HTTP: the server registers http://127.0.0.1/callback
// for a native client, and the client asks for each flow's response on
// the port it is listening on (client.BeginAuthorizationRequest.RedirectPort).
func TestNativeLoopbackRedirectPortEndToEnd(t *testing.T) {
	h := fapitest.New(t, fapitest.Config{
		Profile: server.ProfileFAPISecurity, RedirectURI: "http://127.0.0.1/callback", ApplicationType: storage.ApplicationTypeNative,
	})
	for _, port := range []uint16{51004, 61023} {
		tokens, err := h.RunAuthorizationCodeFlowWithRequest(context.Background(), client.BeginAuthorizationRequest{
			Scope: []string{"openid", "accounts"}, RedirectPort: port,
		})
		if err != nil {
			t.Fatalf("port %d: RunAuthorizationCodeFlowWithRequest: %v", port, err)
		}
		if tokens.AccessToken.Reveal() == "" {
			t.Errorf("port %d: no access token", port)
		}
	}
}

// TestNativePrivateUseRedirectEndToEnd covers a mobile app's private-use
// scheme redirect over real HTTP.
func TestNativePrivateUseRedirectEndToEnd(t *testing.T) {
	h := fapitest.New(t, fapitest.Config{
		Profile: server.ProfileFAPISecurityWithMessageSigning, RedirectURI: "org.idfoundry.oid4vcgo.demowallet:/callback", ApplicationType: storage.ApplicationTypeNative,
	})
	if _, err := h.RunAuthorizationCodeFlow(context.Background(), []string{"openid", "accounts"}); err != nil {
		t.Fatalf("RunAuthorizationCodeFlow: %v", err)
	}
}

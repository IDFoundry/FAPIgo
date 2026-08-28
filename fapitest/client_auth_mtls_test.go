package fapitest_test

import (
	"context"
	"testing"

	"github.com/idfoundry/fapigo/fapitest"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// TestAuthorizationCodeFlowClientAuthSelfSignedTLS and
// TestAuthorizationCodeFlowClientAuthTLSClientAuth are the RFC 8705 §2
// client-authentication axis's counterpart to
// TestAuthorizationCodeFlowMTLSBinding, which only ever exercised §3
// sender-constraining. Before these, ClientAuthMethod's two mTLS values
// had one-side-faked coverage only — server/client_auth_mtls_test.go
// fakes the client presenting a cert directly to a real server, and
// nothing exercised a real client.Client authenticating a real PAR
// request and a real token request with its own certificate over an
// actual TLS connection. SenderConstrain is deliberately left at its
// DPoP default in both tests, isolating the client-authentication axis
// from the token-binding one they're orthogonal to.
func TestAuthorizationCodeFlowClientAuthSelfSignedTLS(t *testing.T) {
	testAuthorizationCodeFlowClientAuth(t, storage.ClientAuthMethodSelfSignedTLSClientAuth)
}

func TestAuthorizationCodeFlowClientAuthTLSClientAuth(t *testing.T) {
	testAuthorizationCodeFlowClientAuth(t, storage.ClientAuthMethodTLSClientAuth)
}

func testAuthorizationCodeFlowClientAuth(t *testing.T, method storage.ClientAuthMethod) {
	t.Helper()
	h := fapitest.New(t, fapitest.Config{
		Profile:          server.ProfileFAPISecurity,
		ClientAuthMethod: method,
	})
	ctx := context.Background()

	// A full flow requires the PAR request (client_id + certificate, no
	// client_assertion) and the token request that follows it to both
	// authenticate successfully — proving fapitest/authserver.go's
	// handlePAR threads the connection's peer certificate through to
	// server.PushAuthorizationRequest, not just handleToken (which
	// sender-constraining's own tests already exercised; RFC 8705 §2
	// client authentication, unlike §3 sender-constraining, applies at
	// every client-authenticating endpoint, PAR included).
	tokens, err := h.RunAuthorizationCodeFlow(ctx, []string{"openid", "accounts"})
	if err != nil {
		t.Fatalf("RunAuthorizationCodeFlow: %v", err)
	}
	if tokens.AccessToken.Reveal() == "" {
		t.Fatalf("AccessToken is empty")
	}
	if !tokens.HasIDToken || tokens.Subject != fapitest.Subject {
		t.Errorf("HasIDToken=%v Subject=%q, want true/%q", tokens.HasIDToken, tokens.Subject, fapitest.Subject)
	}
	if h.MTLSCertificate == nil {
		t.Fatalf("MTLSCertificate is nil, want the certificate the client authenticated with")
	}
}

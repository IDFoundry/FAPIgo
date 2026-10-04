package fapitest_test

import (
	"context"
	"errors"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/fapitest"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// TestRevokeTokenEndToEnd covers RFC 7009 over real HTTP: the client
// revokes its refresh token, the next refresh fails, and revoking again
// still succeeds — for each client authentication the client can use.
func TestRevokeTokenEndToEnd(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  fapitest.Config
	}{
		{"private_key_jwt", fapitest.Config{Profile: server.ProfileFAPISecurity}},
		{"self_signed_tls_client_auth", fapitest.Config{Profile: server.ProfileFAPISecurity, ClientAuthMethod: storage.ClientAuthMethodSelfSignedTLSClientAuth}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := fapitest.New(t, tc.cfg)
			ctx := context.Background()
			tokens, err := h.RunAuthorizationCodeFlow(ctx, offlineScope)
			if err != nil {
				t.Fatalf("RunAuthorizationCodeFlow: %v", err)
			}
			if err := h.Client.RevokeToken(ctx, tokens.RefreshToken); err != nil {
				t.Fatalf("RevokeToken: %v", err)
			}
			if _, err := h.Client.RefreshTokens(ctx, client.RefreshTokenRequest{Tokens: tokens}); err == nil {
				t.Fatal("RefreshTokens with a revoked refresh token succeeded")
			}
			if err := h.Client.RevokeToken(ctx, tokens.RefreshToken); err != nil {
				t.Fatalf("revoking it again: %v, want success", err)
			}
		})
	}
}

// TestRevokeTokenAccessTokenUnsupported covers presenting an access
// token: the server answers unsupported_token_type, which the client
// returns as the server's error.
func TestRevokeTokenAccessTokenUnsupported(t *testing.T) {
	h := fapitest.New(t, fapitest.Config{Profile: server.ProfileFAPISecurity})
	ctx := context.Background()
	tokens, err := h.RunAuthorizationCodeFlow(ctx, offlineScope)
	if err != nil {
		t.Fatalf("RunAuthorizationCodeFlow: %v", err)
	}
	err = h.Client.RevokeToken(ctx, fapi.NewSecret(tokens.AccessToken.Reveal()))
	var cerr *client.Error
	if !errors.As(err, &cerr) {
		t.Fatalf("RevokeToken(access token) = %v, want a *client.Error", err)
	}
	if resp, ok := cerr.ServerResponse(); !ok || resp.Code != "unsupported_token_type" {
		t.Errorf("ServerResponse() = %+v, %v; want unsupported_token_type", resp, ok)
	}
}

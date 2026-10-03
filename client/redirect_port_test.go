package client_test

import (
	"context"
	"testing"

	"github.com/idfoundry/fapigo/client"
)

// TestBeginAuthorizationRedirectPort covers a native app listening on
// loopback on a port picked for the flow (RFC 8252 §7.3): the pushed
// authorization request and the token request both carry
// Config.RedirectURI with that port, and the rest unchanged.
func TestBeginAuthorizationRedirectPort(t *testing.T) {
	for _, tc := range []struct{ configured, want string }{
		{"http://127.0.0.1/callback", "http://127.0.0.1:51004/callback"},
		{"http://127.0.0.1:8400/callback?wallet=1", "http://127.0.0.1:51004/callback?wallet=1"},
		{"http://[::1]/callback", "http://[::1]:51004/callback"},
	} {
		t.Run(tc.configured, func(t *testing.T) {
			c, as, _ := newTestClientWith(t, false, func(cfg *client.Config, _ *client.Dependencies) { cfg.RedirectURI = tc.configured })
			ctx := context.Background()
			session, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid", "accounts"}, RedirectPort: 51004})
			if err != nil {
				t.Fatalf("BeginAuthorization: %v", err)
			}
			if got := as.lastPARForm.Get("redirect_uri"); got != tc.want {
				t.Errorf("PAR redirect_uri = %q, want %q", got, tc.want)
			}
			rawQuery := as.callbackFor(t, session.Handle().String(), "auth-code-123", "")
			if _, err := c.CompleteAuthorization(ctx, client.AuthorizationCallback{RawQuery: rawQuery, Session: session.Handle()}); err != nil {
				t.Fatalf("CompleteAuthorization: %v", err)
			}
			if got := as.lastTokenForm.Get("redirect_uri"); got != tc.want {
				t.Errorf("token redirect_uri = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBeginAuthorizationWithoutRedirectPortSendsTheConfiguredURI(t *testing.T) {
	c, as, _ := newTestClientWith(t, false, func(cfg *client.Config, _ *client.Dependencies) { cfg.RedirectURI = "http://127.0.0.1:8400/callback" })
	if _, err := c.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{Scope: []string{"openid"}}); err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	if got := as.lastPARForm.Get("redirect_uri"); got != "http://127.0.0.1:8400/callback" {
		t.Errorf("PAR redirect_uri = %q, want the configured URI", got)
	}
}

// TestBeginAuthorizationRedirectPortRefusesNonLoopback covers a
// RedirectPort on a redirect URI it can't apply to: refused before
// anything is sent.
func TestBeginAuthorizationRedirectPortRefusesNonLoopback(t *testing.T) {
	for _, configured := range []string{
		"https://rp.example/callback",
		"http://localhost/callback",
		"http://127.0.0.2/callback",
		"com.example.wallet:/callback",
		"http://user@127.0.0.1/callback",
	} {
		t.Run(configured, func(t *testing.T) {
			c, as, _ := newTestClientWith(t, false, func(cfg *client.Config, _ *client.Dependencies) { cfg.RedirectURI = configured })
			_, err := c.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{Scope: []string{"openid"}, RedirectPort: 51004})
			if code := clientErrorCode(t, err); code != client.ErrorInvalidRequest {
				t.Errorf("error code = %q, want %q", code, client.ErrorInvalidRequest)
			}
			if as.lastPARForm != nil {
				t.Error("a pushed authorization request was sent")
			}
		})
	}
}

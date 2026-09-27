package client_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
)

// oauthOnly makes a test client OAuthOnly with no issuer keys and no
// ID token algorithm — what a Wallet talking to a Credential Issuer's
// authorization server configures.
func oauthOnly(cfg *client.Config, deps *client.Dependencies) {
	cfg.OAuthOnly = true
	cfg.Algorithms.IDToken = 0
	deps.IssuerKeys = nil
}

func clientErrorCode(t *testing.T, err error) client.ErrorCode {
	t.Helper()
	var cerr *client.Error
	if !errors.As(err, &cerr) {
		t.Fatalf("error %v is not a *client.Error", err)
	}
	return cerr.Code()
}

func TestOAuthOnlyClientCompletesFlowWithoutIssuerKeys(t *testing.T) {
	c, as, _ := newTestClientWith(t, false, oauthOnly)
	as.omitIDToken = true
	ctx := context.Background()

	session, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"accounts"}})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	result, err := c.CompleteAuthorization(ctx, client.AuthorizationCallback{RawQuery: as.callbackFor(t, session.Handle().String(), "auth-code-123", "")})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	success, ok := result.(client.CompletionSuccess)
	if !ok {
		t.Fatalf("result = %T, want client.CompletionSuccess", result)
	}
	if success.Tokens.AccessToken.Reveal() == "" || success.Tokens.HasIDToken {
		t.Fatalf("tokens = access %q, HasIDToken %v; want an access token and no ID token", success.Tokens.AccessToken.Reveal(), success.Tokens.HasIDToken)
	}
}

func TestOAuthOnlyClientRefusesOpenIDScope(t *testing.T) {
	c, as, _ := newTestClientWith(t, false, oauthOnly)
	_, err := c.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{Scope: []string{"openid", "accounts"}})
	if code := clientErrorCode(t, err); code != client.ErrorInvalidRequest {
		t.Fatalf("error code = %q, want %q", code, client.ErrorInvalidRequest)
	}
	if as.parCallCount != 0 {
		t.Fatalf("PAR called %d times, want 0 — the scope must be refused before any request", as.parCallCount)
	}
}

// TestOAuthOnlyClientRejectsUnrequestedIDToken covers a server that
// sends an id_token anyway: an OAuthOnly client has no issuer keys to
// check it with, so the response is rejected rather than silently
// accepted or dropped.
func TestOAuthOnlyClientRejectsUnrequestedIDToken(t *testing.T) {
	c, as, _ := newTestClientWith(t, false, oauthOnly)
	ctx := context.Background()

	session, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"accounts"}})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	_, err = c.CompleteAuthorization(ctx, client.AuthorizationCallback{RawQuery: as.callbackFor(t, session.Handle().String(), "auth-code-123", "")})
	if code := clientErrorCode(t, err); code != client.ErrorInvalidResponse {
		t.Fatalf("error code = %q, want %q", code, client.ErrorInvalidResponse)
	}
}

func TestOAuthOnlyClientRefusesOpenIDScopeForCIBA(t *testing.T) {
	cfg := validConfig(t)
	cfg.OAuthOnly = true
	cfg.Algorithms.IDToken = 0
	cfg.Endpoints.BackchannelAuthentication = cfg.Endpoints.Token
	cfg.Algorithms.BackchannelAuthenticationRequest = fapi.ES256
	cfg.Limits.BackchannelAuthenticationRequestLifetime = time.Minute
	deps := validDependencies(t)
	deps.IssuerKeys = nil
	oc, err := client.New(cfg, deps)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	_, err = oc.BeginBackchannelAuthentication(context.Background(), client.BeginBackchannelAuthenticationRequest{
		Scope: []string{"openid"}, LoginHint: "user@example.com",
	})
	if code := clientErrorCode(t, err); code != client.ErrorInvalidRequest {
		t.Fatalf("error code = %q, want %q", code, client.ErrorInvalidRequest)
	}
}

func TestNewOAuthOnlyIssuerKeysRequirement(t *testing.T) {
	cases := map[string]struct {
		mutate  func(*client.Config)
		wantErr bool
	}{
		"oauth_only, nothing issuer-signed verified": {func(*client.Config) {}, false},
		"oauth_only with JARM": {func(c *client.Config) {
			c.Profile = client.ProfileFAPISecurityWithMessageSigning
			c.Algorithms.RequestObject = fapi.ES256
			c.Algorithms.JARM = fapi.ES256
			c.Limits.RequestObjectLifetime = time.Minute
			c.Limits.MaxJARMResponseLifetime = time.Minute
		}, true},
		"oauth_only with signed UserInfo": {func(c *client.Config) {
			c.Algorithms.UserInfo = fapi.ES256
			c.Endpoints.UserInfo = c.Endpoints.Token
		}, true},
		"not oauth_only": {func(c *client.Config) { c.OAuthOnly = false; c.Algorithms.IDToken = fapi.ES256 }, true},
		"oauth_only with ID token encryption": {func(c *client.Config) {
			c.Algorithms.IDTokenKeyManagement = fapi.RSAOAEP256
			c.Algorithms.IDTokenContentEncryption = fapi.A256GCM
		}, true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := validConfig(t)
			cfg.OAuthOnly = true
			cfg.Algorithms.IDToken = 0
			tc.mutate(&cfg)
			deps := validDependencies(t)
			deps.IssuerKeys = nil
			_, err := client.New(cfg, deps)
			if (err != nil) != tc.wantErr {
				t.Fatalf("client.New() error = %v, wantErr %v", err, tc.wantErr)
			}
			// Every rejection here must come from the oauth_only rules,
			// not some unrelated requirement the case happens to miss.
			if err != nil && !strings.Contains(err.Error(), "oauth_only") {
				t.Fatalf("client.New() error = %v, want one about oauth_only", err)
			}
		})
	}
}

// TestNewMaxIDTokenLifetimeRequirement covers Limits.MaxIDTokenLifetime
// being required exactly when the client can receive an ID token — the
// same condition as Algorithms.IDToken — so an OAuthOnly or
// client_credentials-only client isn't made to set a limit nothing
// reads.
func TestNewMaxIDTokenLifetimeRequirement(t *testing.T) {
	noBrowserFlow := func(c *client.Config) {
		c.Endpoints.Authorization = fapi.URL{}
		c.Endpoints.PushedAuthorizationRequest = fapi.URL{}
	}
	cases := map[string]struct {
		mutate  func(*client.Config, *client.Dependencies)
		wantErr bool
	}{
		"browser flow": {func(*client.Config, *client.Dependencies) {}, true},
		"browser flow, oauth_only": {func(c *client.Config, d *client.Dependencies) {
			c.OAuthOnly = true
			c.Algorithms.IDToken = 0
			d.IssuerKeys = nil
		}, false},
		"client_credentials only": {func(c *client.Config, _ *client.Dependencies) { noBrowserFlow(c) }, false},
		"CIBA": {func(c *client.Config, _ *client.Dependencies) {
			noBrowserFlow(c)
			c.Endpoints.BackchannelAuthentication = c.Endpoints.Token
			c.Algorithms.BackchannelAuthenticationRequest = fapi.ES256
			c.Limits.BackchannelAuthenticationRequestLifetime = time.Minute
		}, true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := validConfig(t)
			deps := validDependencies(t)
			tc.mutate(&cfg, &deps)
			cfg.Limits.MaxIDTokenLifetime = 0
			_, err := client.New(cfg, deps)
			if (err != nil) != tc.wantErr {
				t.Fatalf("client.New() error = %v, wantErr %v", err, tc.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), "max_id_token_lifetime") {
				t.Fatalf("client.New() error = %v, want one about max_id_token_lifetime", err)
			}
		})
	}
}

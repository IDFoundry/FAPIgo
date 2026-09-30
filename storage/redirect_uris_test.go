package storage

import (
	"testing"

	fapi "github.com/idfoundry/fapigo"
)

// TestRedirectURIsOptionalWithoutAuthorizationCode covers #452: only the
// authorization code grant redirects, so a client registered only for
// CIBA or client credentials needs no redirect URI — and can't use that
// grant — while a client with neither still does.
func TestRedirectURIsOptionalWithoutAuthorizationCode(t *testing.T) {
	base := RegisteredClientConfig{ID: "c", ClientAssertionAlgorithm: fapi.ES256, AllowedScopes: []string{"openid"}}
	for name, tc := range map[string]struct {
		mutate  func(*RegisteredClientConfig)
		wantErr bool
	}{
		"CIBA only":               {mutate: func(c *RegisteredClientConfig) { c.BackchannelAuthenticationRequestAlgorithm = fapi.ES256 }},
		"client credentials only": {mutate: func(c *RegisteredClientConfig) { c.AllowsClientCredentialsGrant = true }},
		"neither":                 {mutate: func(*RegisteredClientConfig) {}, wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := base
			tc.mutate(&cfg)
			c, err := NewRegisteredClient(cfg)
			if tc.wantErr {
				if err == nil {
					t.Fatal("NewRegisteredClient(no redirect URIs, no other grant) = nil error, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("NewRegisteredClient: %v", err)
			}
			if c.AllowsAuthorizationCodeGrant() {
				t.Error("AllowsAuthorizationCodeGrant() = true for a client with no redirect URI")
			}
		})
	}
	withRedirect := base
	withRedirect.RedirectURIs = []fapi.RegisteredRedirectURI{"https://rp.example/cb"}
	c, err := NewRegisteredClient(withRedirect)
	if err != nil || !c.AllowsAuthorizationCodeGrant() {
		t.Errorf("client with a redirect URI: AllowsAuthorizationCodeGrant() = %v, err %v", c.AllowsAuthorizationCodeGrant(), err)
	}
}

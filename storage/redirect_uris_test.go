package storage

import (
	"slices"
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

// TestRegisteredClientRedirectURIs: the registered redirect URIs come
// back in registration order, as a copy the caller can't use to change
// the registration.
func TestRegisteredClientRedirectURIs(t *testing.T) {
	want := []fapi.RegisteredRedirectURI{"https://rp.example/b", "https://rp.example/a"}
	c, err := NewRegisteredClient(RegisteredClientConfig{ID: "c", RedirectURIs: want, ClientAssertionAlgorithm: fapi.ES256, AllowedScopes: []string{"openid"}})
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}
	got := c.RedirectURIs()
	if !slices.Equal(got, want) {
		t.Fatalf("RedirectURIs() = %v, want %v", got, want)
	}
	got[0] = "https://attacker.example/cb"
	if c.HasRedirectURI("https://attacker.example/cb") || !slices.Equal(c.RedirectURIs(), want) {
		t.Fatal("changing RedirectURIs()'s result changed the registration")
	}
}

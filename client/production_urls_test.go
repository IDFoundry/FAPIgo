package client_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
)

// TestNewRejectsLoopbackHTTPURLsUnderProduction: fapi.AllowLoopbackHTTP
// is for a local development authorization server; under
// AssuranceProduction the client refuses an issuer or endpoint parsed
// with it, as server.New does for its own.
func TestNewRejectsLoopbackHTTPURLsUnderProduction(t *testing.T) {
	issuer, err := fapi.ParseIssuerURL("http://127.0.0.1:9999", fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}
	endpoint, err := fapi.ParseEndpointURL("http://127.0.0.1:9999/ep", fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	cases := map[string]func(*client.Config){
		"issuer":                                 func(c *client.Config) { c.Issuer = issuer },
		"endpoints.authorization":                func(c *client.Config) { c.Endpoints.Authorization = endpoint },
		"endpoints.token":                        func(c *client.Config) { c.Endpoints.Token = endpoint },
		"endpoints.pushed_authorization_request": func(c *client.Config) { c.Endpoints.PushedAuthorizationRequest = endpoint },
		"endpoints.userinfo":                     func(c *client.Config) { c.Endpoints.UserInfo = endpoint },
		"endpoints.backchannel_authentication":   func(c *client.Config) { c.Endpoints.BackchannelAuthentication = endpoint },
		"endpoints.revocation":                   func(c *client.Config) { c.Endpoints.Revocation = endpoint },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := validConfig(t)
			cfg.Assurance = client.AssuranceProduction
			mutate(&cfg)
			_, err := client.New(cfg, productionDeps(t))
			if err == nil || !strings.Contains(err.Error(), name+" was parsed with fapi.AllowLoopbackHTTP") {
				t.Fatalf("New(production, loopback %s) error = %v, want it refused by name", name, err)
			}
		})
	}

	t.Run("development accepts loopback", func(t *testing.T) {
		cfg := validConfig(t)
		cfg.Assurance = client.AssuranceDevelopment
		cfg.Issuer = issuer
		cfg.Endpoints.Token = endpoint
		cfg.Endpoints.UserInfo = endpoint
		if _, err := client.New(cfg, validDependencies(t)); err != nil {
			t.Fatalf("New(development, loopback): %v", err)
		}
	})

	// A native app's loopback redirect URI is http by definition (RFC
	// 8252 §7.3) and stays valid in production.
	t.Run("production accepts a loopback redirect URI", func(t *testing.T) {
		cfg := validConfig(t)
		cfg.Assurance = client.AssuranceProduction
		cfg.RedirectURI = "http://127.0.0.1/callback"
		if _, err := client.New(cfg, productionDeps(t)); err != nil {
			t.Fatalf("New(production, loopback redirect URI): %v", err)
		}
	})
}

// countingHTTP records whether a request was sent at all.
type countingHTTP struct{ calls *int }

func (c countingHTTP) Do(*http.Request) (*http.Response, error) {
	*c.calls++
	return nil, errors.New("countingHTTP: no response")
}

func TestProtectedResourceDoRejectsLoopbackHTTPUnderProduction(t *testing.T) {
	for _, tc := range []struct {
		assurance client.AssuranceLevel
		refused   bool
	}{
		{client.AssuranceProduction, true},
		{client.AssuranceDevelopment, false},
	} {
		t.Run(fmt.Sprint(tc.assurance), func(t *testing.T) {
			cfg := validConfig(t)
			cfg.Assurance = tc.assurance
			deps := validDependencies(t)
			if tc.assurance == client.AssuranceProduction {
				deps = productionDeps(t)
			}
			var calls int
			deps.HTTP = countingHTTP{calls: &calls}
			c, err := client.New(cfg, deps)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			rc := c.ProtectedResource(client.TokenSet{AccessToken: fapi.NewSecret("test-access-token")})
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://127.0.0.1:9999/accounts", nil)
			if err != nil {
				t.Fatalf("NewRequestWithContext: %v", err)
			}
			_, err = rc.Do(context.Background(), req)
			refused := err != nil && strings.Contains(err.Error(), "protected resource URL was parsed with fapi.AllowLoopbackHTTP")
			if refused != tc.refused {
				t.Fatalf("Do(loopback http) error = %v, want refused = %v", err, tc.refused)
			}
			if tc.refused && calls != 0 {
				t.Fatalf("Do sent %d request(s), want none", calls)
			}
			if !tc.refused && calls != 1 {
				t.Fatalf("Do sent %d request(s), want 1", calls)
			}
		})
	}
}

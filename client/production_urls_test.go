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
			calls, err := doLoopbackResourceRequest(t, tc.assurance)
			refused := err != nil && strings.Contains(err.Error(), "protected resource URL was parsed with fapi.AllowLoopbackHTTP")
			if refused != tc.refused {
				t.Fatalf("Do(loopback http) error = %v, want refused = %v", err, tc.refused)
			}
			wantCalls := 1
			if tc.refused {
				wantCalls = 0
			}
			if calls != wantCalls {
				t.Fatalf("Do sent %d request(s), want %d", calls, wantCalls)
			}
		})
	}
}

// doLoopbackResourceRequest builds a client at assurance and sends a
// protected resource request to a loopback http URL through it,
// returning how many requests reached the HTTP client and Do's error.
func doLoopbackResourceRequest(t *testing.T, assurance client.AssuranceLevel) (int, error) {
	t.Helper()
	cfg := validConfig(t)
	cfg.Assurance = assurance
	deps := validDependencies(t)
	if assurance == client.AssuranceProduction {
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
	return calls, err
}

// TestNewValidatesRedirectURI: Config.RedirectURI must be one an
// authorization server following FAPI 2.0 would accept — https, a
// native app's loopback http or a private-use scheme — checked at New;
// under production a loopback redirect names the IP literal, not
// localhost.
func TestNewValidatesRedirectURI(t *testing.T) {
	for name, tc := range map[string]struct {
		uri        string
		production bool
		ok         bool
	}{
		"https":                       {"https://rp.example.com/cb", true, true},
		"loopback IP literal":         {"http://127.0.0.1/cb", true, true},
		"loopback IPv6 literal":       {"http://[::1]:8400/cb", true, true},
		"private-use scheme":          {"com.example.wallet:/cb", true, true},
		"localhost, development":      {"http://localhost/cb", false, true},
		"localhost, production":       {"http://localhost/cb", true, false},
		"http to a non-loopback host": {"http://rp.example.com/cb", false, false},
		"fragment":                    {"https://rp.example.com/cb#x", false, false},
		"credentials":                 {"http://user@127.0.0.1/cb", false, false},
		"private-use with //":         {"com.example.wallet://cb", false, false},
		"not absolute":                {"/cb", false, false},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, deps := validConfig(t), validDependencies(t)
			if tc.production {
				cfg.Assurance, deps = client.AssuranceProduction, productionDeps(t)
			}
			cfg.RedirectURI = tc.uri
			_, err := client.New(cfg, deps)
			if tc.ok && err != nil {
				t.Fatalf("New(%q) = %v, want accepted", tc.uri, err)
			}
			if !tc.ok && (err == nil || !strings.Contains(err.Error(), "redirect_uri")) {
				t.Fatalf("New(%q) = %v, want a redirect_uri refusal", tc.uri, err)
			}
		})
	}
}

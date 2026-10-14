package client_test

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/fapihttp"
)

// TestNewProductionRequiresHardenedHTTP: under AssuranceProduction,
// Dependencies.HTTP must be fapihttp.NewClient's client (or a copy),
// still intact and allowing no loopback address; development takes any
// HTTP client.
func TestNewProductionRequiresHardenedHTTP(t *testing.T) {
	withCert := fapihttp.RecommendedTransportConfig()
	withCert.Certificates = []tls.Certificate{{}}
	withPrivate := fapihttp.RecommendedTransportConfig()
	withPrivate.AllowedPrivateHosts = []string{"as.internal"}
	withLoopback := fapihttp.RecommendedTransportConfig()
	withLoopback.AllowLoopbackHosts = true

	for name, tc := range map[string]struct {
		http    func(t *testing.T) fapihttp.HTTPClient
		refusal string // "" when accepted
	}{
		"NewClient": {func(t *testing.T) fapihttp.HTTPClient {
			return hardenedHTTPClient(t, fapihttp.RecommendedTransportConfig())
		}, ""},
		"a copy with a timeout": {func(t *testing.T) fapihttp.HTTPClient {
			c := *hardenedHTTPClient(t, fapihttp.RecommendedTransportConfig())
			c.Timeout = 30
			return &c
		}, ""},
		"client certificate": {func(t *testing.T) fapihttp.HTTPClient { return hardenedHTTPClient(t, withCert) }, ""},
		"allowed private host": {func(t *testing.T) fapihttp.HTTPClient {
			return hardenedHTTPClient(t, withPrivate)
		}, ""},
		"not an *http.Client": {func(*testing.T) fapihttp.HTTPClient { return noopHTTPClient{} }, "not client_test.noopHTTPClient"},
		"default client":      {func(*testing.T) fapihttp.HTTPClient { return http.DefaultClient }, "with its transport as NewClient built it"},
		"proxied": {func(t *testing.T) fapihttp.HTTPClient {
			c := hardenedHTTPClient(t, fapihttp.RecommendedTransportConfig())
			c.Transport.(*http.Transport).Proxy = func(*http.Request) (*url.URL, error) { return nil, nil }
			return c
		}, "with its transport as NewClient built it"},
		"loopback allowed": {func(t *testing.T) fapihttp.HTTPClient {
			return hardenedHTTPClient(t, withLoopback)
		}, "allows loopback addresses"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := validConfig(t)
			cfg.Assurance = client.AssuranceProduction
			deps := productionDeps(t)
			deps.HTTP = tc.http(t)
			_, err := client.New(cfg, deps)
			switch {
			case tc.refusal == "" && err != nil:
				t.Fatalf("New(production) = %v, want accepted", err)
			case tc.refusal != "" && (err == nil || !strings.Contains(err.Error(), tc.refusal)):
				t.Fatalf("New(production) = %v, want refused (%q)", err, tc.refusal)
			}

			cfg.Assurance = client.AssuranceDevelopment
			devDeps := validDependencies(t)
			devDeps.HTTP = tc.http(t)
			if _, err := client.New(cfg, devDeps); err != nil {
				t.Fatalf("New(development) = %v, want accepted", err)
			}
		})
	}
}

package client_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/keys"
)

// TestNewProductionRefusesLoopbackJWKSIssuerKeys: a
// keys.JWKSIssuerKeySource fetching through a fapihttp client with a
// loopback exception, or over a plain http.Client rather than
// fapihttp.NewClient's, doesn't declare LiveFetchHardened, so a
// production client refuses it; one over NewClient's client without an
// exception is accepted.
func TestNewProductionRefusesLoopbackJWKSIssuerKeys(t *testing.T) {
	hardened, err := fapihttp.NewClient(fapihttp.RecommendedTransportConfig())
	if err != nil {
		t.Fatalf("fapihttp.NewClient: %v", err)
	}
	for name, tc := range map[string]struct {
		transport fapihttp.HTTPClient
		cfg       fapihttp.Config
		refused   bool
	}{
		"no exceptions":        {hardened, fapihttp.Config{}, false},
		"allow loopback hosts": {hardened, fapihttp.Config{AllowLoopbackHosts: true}, true},
		"plain http.Client":    {&http.Client{}, fapihttp.Config{}, true},
	} {
		t.Run(name, func(t *testing.T) {
			tc.cfg.MaxResponseBytes, tc.cfg.RequestTimeout = 1<<16, time.Second
			fetcher, err := fapihttp.New(tc.transport, tc.cfg)
			if err != nil {
				t.Fatalf("fapihttp.New: %v", err)
			}
			jwksURI, err := fapi.ParseEndpointURL("https://issuer.example.com/jwks")
			if err != nil {
				t.Fatalf("ParseEndpointURL: %v", err)
			}
			source, err := keys.NewJWKSIssuerKeySource(fetcher, jwksURI, time.Minute)
			if err != nil {
				t.Fatalf("NewJWKSIssuerKeySource: %v", err)
			}
			cfg := validConfig(t)
			asProduction(&cfg)
			cfg.AuthorizationResponseIssPolicy = client.RequireAuthorizationResponseIss
			deps := productionDeps(t)
			deps.IssuerKeys = source
			_, err = client.New(cfg, deps)
			if tc.refused {
				if err == nil || !strings.Contains(err.Error(), "issuer_keys") {
					t.Fatalf("New(production, JWKS source with %s) error = %v, want it refused", name, err)
				}
			} else if err != nil {
				t.Fatalf("New(production, JWKS source with %s): %v", name, err)
			}
		})
	}
}

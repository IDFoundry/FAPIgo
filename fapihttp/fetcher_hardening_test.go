package fapihttp_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/idfoundry/fapigo/fapihttp"
)

func fetcher(t *testing.T, transport fapihttp.HTTPClient, cfg fapihttp.Config) *fapihttp.Client {
	t.Helper()
	f, err := fapihttp.New(transport, cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return f
}

// TestClientHardeningFollowsItsTransport: a fetcher over NewClient's
// client is hardened, with the transport's exceptions; one over any
// other HTTPClient isn't; and HardenedForProduction also refuses a
// loopback exception on either the transport or the fetcher's Config,
// but not an allowed private host.
func TestClientHardeningFollowsItsTransport(t *testing.T) {
	loopbackTransport := fapihttp.RecommendedTransportConfig()
	loopbackTransport.AllowLoopbackHosts = true
	privateTransport := fapihttp.RecommendedTransportConfig()
	privateTransport.AllowedPrivateHosts = []string{"as.internal"}
	loopbackConfig := fapihttp.RecommendedConfig()
	loopbackConfig.AllowLoopbackHosts = true

	tests := map[string]struct {
		transport      fapihttp.HTTPClient
		cfg            fapihttp.Config
		wantHardened   bool
		wantProduction bool
	}{
		"NewClient":                     {hardenedClient(t, fapihttp.RecommendedTransportConfig()), fapihttp.RecommendedConfig(), true, true},
		"NewClient, private host":       {hardenedClient(t, privateTransport), fapihttp.RecommendedConfig(), true, true},
		"NewClient, loopback transport": {hardenedClient(t, loopbackTransport), fapihttp.RecommendedConfig(), true, false},
		"NewClient, loopback config":    {hardenedClient(t, fapihttp.RecommendedTransportConfig()), loopbackConfig, true, false},
		"http.DefaultClient":            {http.DefaultClient, fapihttp.RecommendedConfig(), false, false},
		"plain client":                  {&http.Client{}, fapihttp.RecommendedConfig(), false, false},
		"wrapper":                       {doerFunc(http.DefaultClient.Do), fapihttp.RecommendedConfig(), false, false},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			f := fetcher(t, tc.transport, tc.cfg)
			if _, ok := f.Hardening(); ok != tc.wantHardened {
				t.Errorf("Hardening ok = %v, want %v", ok, tc.wantHardened)
			}
			if got := f.HardenedForProduction(); got != tc.wantProduction {
				t.Errorf("HardenedForProduction = %v, want %v", got, tc.wantProduction)
			}
		})
	}
}

// TestClientHardeningRechecksItsTransport: a transport weakened after
// New stops counting as hardened from then on.
func TestClientHardeningRechecksItsTransport(t *testing.T) {
	transport := hardenedClient(t, fapihttp.RecommendedTransportConfig())
	f := fetcher(t, transport, fapihttp.RecommendedConfig())
	if !f.HardenedForProduction() {
		t.Fatal("HardenedForProduction before tampering = false, want true")
	}
	transport.Transport.(*http.Transport).Proxy = func(*http.Request) (*url.URL, error) { return nil, nil }
	if _, ok := f.Hardening(); ok {
		t.Error("Hardening after a Proxy was set = true, want false")
	}
	if f.HardenedForProduction() {
		t.Error("HardenedForProduction after a Proxy was set = true, want false")
	}
}

type doerFunc func(*http.Request) (*http.Response, error)

func (f doerFunc) Do(r *http.Request) (*http.Response, error) { return f(r) }

package server_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/backchannelhttp"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// declaredBackchannelStore is a memstore backchannel store declaring the
// capabilities AssuranceProduction requires, so these tests isolate the
// notifier check.
type declaredBackchannelStore struct {
	storage.BackchannelAuthenticationStore
}

func (declaredBackchannelStore) Capabilities() storage.Capabilities {
	return storage.Capabilities{Durable: true, AtomicConsume: true}
}

type undeclaredNotifier struct{}

func (undeclaredNotifier) Notify(context.Context, server.BackchannelNotification) error { return nil }

type declaringNotifier struct{ hardened bool }

func (declaringNotifier) Notify(context.Context, server.BackchannelNotification) error { return nil }

func (n declaringNotifier) BackchannelNotifierCapabilities() server.BackchannelNotifierCapabilities {
	return server.BackchannelNotifierCapabilities{OutboundHardened: n.hardened}
}

// cibaConfigAndDeps returns a CIBA-enabled configuration at assurance,
// with every other production requirement met.
func cibaConfigAndDeps(t *testing.T, assurance server.AssuranceLevel, notifier server.BackchannelNotifier) (server.Config, server.Dependencies) {
	t.Helper()
	cfg := validConfig(t)
	cfg.Assurance = assurance
	cfg.Deployment = server.DeploymentSingleInstance
	backchannelEndpoint, err := fapi.ParseEndpointURL(testBackchannelAuthenticationEndpoint)
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	cfg.Endpoints.BackchannelAuthentication = backchannelEndpoint
	cfg.Algorithms.BackchannelAuthenticationRequest = server.AlgorithmSet{fapi.ES256}
	cfg.Limits.BackchannelAuthenticationRequestLifetime = 2 * time.Minute
	cfg.Limits.MaxBackchannelAuthenticationRequestLifetime = time.Minute
	cfg.Limits.BackchannelAuthenticationPollInterval = time.Millisecond
	deps := validDependencies()
	deps.Audit = &fakeAuditSink{}
	deps.Backchannel = declaredBackchannelStore{memstore.NewBackchannelAuthenticationStore()}
	deps.BackchannelNotifier = notifier
	return cfg, deps
}

func TestNewProductionRequiresHardenedBackchannelNotifier(t *testing.T) {
	refused := map[string]struct {
		notifier server.BackchannelNotifier
		want     string
	}{
		"undeclared":            {undeclaredNotifier{}, "must implement server.BackchannelNotifierAssurance"},
		"undeclared pointer":    {&undeclaredNotifier{}, "must implement server.BackchannelNotifierAssurance"},
		"declares not hardened": {declaringNotifier{}, "must declare OutboundHardened"},
		"pointer, not hardened": {&declaringNotifier{}, "must declare OutboundHardened"},
	}
	for name, tc := range refused {
		t.Run(name, func(t *testing.T) {
			cfg, deps := cibaConfigAndDeps(t, server.AssuranceProduction, tc.notifier)
			if _, err := server.New(cfg, deps); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("New(production, %s notifier) error = %v, want %q", name, err, tc.want)
			}
		})
	}

	notifier, err := backchannelhttp.New(backchannelhttp.Config{
		Transport: fapihttp.TransportConfig{DialTimeout: time.Second, TLSHandshakeTimeout: time.Second},
		Timeout:   time.Second,
	})
	if err != nil {
		t.Fatalf("backchannelhttp.New: %v", err)
	}
	accepted := map[string]server.BackchannelNotifier{
		"backchannelhttp.Notifier":          notifier,
		"NoBackchannelNotifications":        server.NoBackchannelNotifications{},
		"*NoBackchannelNotifications":       &server.NoBackchannelNotifications{},
		"custom, declares hardened":         declaringNotifier{hardened: true},
		"custom pointer, declares hardened": &declaringNotifier{hardened: true},
	}
	for name, n := range accepted {
		t.Run(name, func(t *testing.T) {
			cfg, deps := cibaConfigAndDeps(t, server.AssuranceProduction, n)
			if _, err := server.New(cfg, deps); err != nil {
				t.Fatalf("New(production, %s): %v", name, err)
			}
		})
	}

	t.Run("development accepts an undeclared notifier", func(t *testing.T) {
		cfg, deps := cibaConfigAndDeps(t, server.AssuranceDevelopment, undeclaredNotifier{})
		if _, err := server.New(cfg, deps); err != nil {
			t.Fatalf("New(development, undeclared notifier): %v", err)
		}
	})

	t.Run("production without CIBA ignores the notifier", func(t *testing.T) {
		cfg := validConfig(t)
		cfg.Assurance = server.AssuranceProduction
		cfg.Deployment = server.DeploymentSingleInstance
		deps := validDependencies()
		deps.Audit = &fakeAuditSink{}
		deps.BackchannelNotifier = undeclaredNotifier{}
		if _, err := server.New(cfg, deps); err != nil {
			t.Fatalf("New(production, no CIBA, undeclared notifier): %v", err)
		}
	})
}

// TestNewProductionRefusesLoopbackOutboundExceptions: a loopback
// exception in fapihttp's config is for local development only, so a
// backchannelhttp.Notifier, or the federation fetcher, built with one
// isn't hardened enough for AssuranceProduction. AllowedPrivateHosts
// names the operator's own hosts and stays acceptable.
func TestNewProductionRefusesLoopbackOutboundExceptions(t *testing.T) {
	exceptions := map[string]fapihttp.TransportConfig{
		"allow loopback hosts":   {AllowLoopbackHosts: true},
		"allow loopback http":    {AllowLoopbackHTTP: true},
		"allowed loopback hosts": {AllowedLoopbackHosts: []string{"suite.example.com"}},
	}
	notifierWith := func(t *testing.T, transport fapihttp.TransportConfig) *backchannelhttp.Notifier {
		t.Helper()
		transport.DialTimeout, transport.TLSHandshakeTimeout = time.Second, time.Second
		n, err := backchannelhttp.New(backchannelhttp.Config{Transport: transport, Timeout: time.Second})
		if err != nil {
			t.Fatalf("backchannelhttp.New: %v", err)
		}
		return n
	}
	fetcherWith := func(t *testing.T, transport fapihttp.TransportConfig) *fapihttp.Client {
		t.Helper()
		c, err := fapihttp.New(&http.Client{}, fapihttp.Config{
			MaxResponseBytes: 1 << 16, RequestTimeout: time.Second,
			AllowLoopbackHosts: transport.AllowLoopbackHosts, AllowLoopbackHTTP: transport.AllowLoopbackHTTP,
			AllowedLoopbackHosts: transport.AllowedLoopbackHosts, AllowedPrivateHosts: transport.AllowedPrivateHosts,
		})
		if err != nil {
			t.Fatalf("fapihttp.New: %v", err)
		}
		return c
	}
	for name, transport := range exceptions {
		t.Run("notifier, "+name, func(t *testing.T) {
			cfg, deps := cibaConfigAndDeps(t, server.AssuranceProduction, notifierWith(t, transport))
			if _, err := server.New(cfg, deps); err == nil || !strings.Contains(err.Error(), "must declare OutboundHardened") {
				t.Fatalf("New(production, notifier with %s) error = %v, want it refused", name, err)
			}
		})
		t.Run("federation http, "+name, func(t *testing.T) {
			cfg, deps := cibaConfigAndDeps(t, server.AssuranceProduction, server.NoBackchannelNotifications{})
			deps.FederationHTTP = fetcherWith(t, transport)
			if _, err := server.New(cfg, deps); err == nil || !strings.Contains(err.Error(), "federation_http must not grant a loopback exception") {
				t.Fatalf("New(production, federation fetcher with %s) error = %v, want it refused", name, err)
			}
		})
		t.Run("development accepts "+name, func(t *testing.T) {
			cfg, deps := cibaConfigAndDeps(t, server.AssuranceDevelopment, notifierWith(t, transport))
			deps.FederationHTTP = fetcherWith(t, transport)
			if _, err := server.New(cfg, deps); err != nil {
				t.Fatalf("New(development, %s): %v", name, err)
			}
		})
	}
	t.Run("allowed private hosts stay hardened", func(t *testing.T) {
		private := fapihttp.TransportConfig{AllowedPrivateHosts: []string{"notify.internal"}}
		cfg, deps := cibaConfigAndDeps(t, server.AssuranceProduction, notifierWith(t, private))
		deps.FederationHTTP = fetcherWith(t, private)
		if _, err := server.New(cfg, deps); err != nil {
			t.Fatalf("New(production, AllowedPrivateHosts): %v", err)
		}
	})
}

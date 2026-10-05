package server_test

import (
	"context"
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
		deps := validDependencies()
		deps.Audit = &fakeAuditSink{}
		deps.BackchannelNotifier = undeclaredNotifier{}
		if _, err := server.New(cfg, deps); err != nil {
			t.Fatalf("New(production, no CIBA, undeclared notifier): %v", err)
		}
	})
}

package server_test

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

func validConfig(t *testing.T) server.Config {
	t.Helper()
	issuer, err := fapi.ParseIssuerURL(testIssuer)
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}
	return server.Config{
		Issuer:    issuer,
		Endpoints: testEndpoints(t),
		Profile:   server.ProfileFAPISecurity,
		Algorithms: server.AlgorithmPolicy{
			ClientAssertion: server.AlgorithmSet{fapi.ES256},
			RequestObject:   server.AlgorithmSet{fapi.ES256},
			AccessToken:     fapi.ES256,
			IDToken:         fapi.ES256,
		},
		Limits: server.Limits{
			PushedRequestLifetime:      90 * time.Second,
			MaxClientAssertionLifetime: time.Minute,
			MaxRequestObjectLifetime:   time.Minute,
			InteractionLifetime:        5 * time.Minute,
			AuthorizationCodeLifetime:  time.Minute,
			AccessTokenLifetime:        5 * time.Minute,
			IDTokenLifetime:            5 * time.Minute,
			RefreshTokenLifetime:       5 * time.Minute,
			MaxDPoPProofAge:            time.Minute,
			MaxClockSkew:               5 * time.Second,
		},
		Assurance: server.AssuranceDevelopment,
	}
}

func validDependencies() server.Dependencies {
	return server.Dependencies{
		Clients:      &fakeClientRepository{clients: map[fapi.ClientID]storage.RegisteredClient{}},
		Transactions: &fakeTransactionStore{},
		Grants:       &fakeGrantStore{},
		Replay:       &fakeReplayStore{},
		ClientKeys:   &fakeClientKeySource{},
		Keys:         &fakeKeyManager{},
		Clock:        fixedClock{now: time.Now()},
		Random:       rand.Reader,
	}
}

func TestNewAcceptsValidConfig(t *testing.T) {
	if _, err := server.New(validConfig(t), validDependencies()); err != nil {
		t.Fatalf("New: %v", err)
	}
}

func TestNewRejectsInvalidConfig(t *testing.T) {
	cases := map[string]func(*server.Config){
		"zero issuer":                      func(c *server.Config) { c.Issuer = fapi.URL{} },
		"zero token endpoint":              func(c *server.Config) { c.Endpoints.Token = fapi.URL{} },
		"zero authorization endpoint":      func(c *server.Config) { c.Endpoints.Authorization = fapi.URL{} },
		"zero par endpoint":                func(c *server.Config) { c.Endpoints.PushedAuthorizationRequest = fapi.URL{} },
		"zero jwks endpoint":               func(c *server.Config) { c.Endpoints.JWKS = fapi.URL{} },
		"invalid profile":                  func(c *server.Config) { c.Profile = 0 },
		"empty client assertion algs":      func(c *server.Config) { c.Algorithms.ClientAssertion = nil },
		"empty request object algs":        func(c *server.Config) { c.Algorithms.RequestObject = nil },
		"invalid access token alg":         func(c *server.Config) { c.Algorithms.AccessToken = 0 },
		"invalid id token alg":             func(c *server.Config) { c.Algorithms.IDToken = 0 },
		"zero pushed request lifetime":     func(c *server.Config) { c.Limits.PushedRequestLifetime = 0 },
		"zero max assertion lifetime":      func(c *server.Config) { c.Limits.MaxClientAssertionLifetime = 0 },
		"zero max request object lifetime": func(c *server.Config) { c.Limits.MaxRequestObjectLifetime = 0 },
		"zero interaction lifetime":        func(c *server.Config) { c.Limits.InteractionLifetime = 0 },
		"zero authorization code lifetime": func(c *server.Config) { c.Limits.AuthorizationCodeLifetime = 0 },
		"zero access token lifetime":       func(c *server.Config) { c.Limits.AccessTokenLifetime = 0 },
		"zero id token lifetime":           func(c *server.Config) { c.Limits.IDTokenLifetime = 0 },
		"zero refresh token lifetime":      func(c *server.Config) { c.Limits.RefreshTokenLifetime = 0 },
		"zero max dpop proof age":          func(c *server.Config) { c.Limits.MaxDPoPProofAge = 0 },
		"negative clock skew":              func(c *server.Config) { c.Limits.MaxClockSkew = -time.Second },
		"invalid assurance":                func(c *server.Config) { c.Assurance = 0 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := validConfig(t)
			mutate(&cfg)
			if _, err := server.New(cfg, validDependencies()); err == nil {
				t.Fatalf("New(%s) = nil error, want error", name)
			}
		})
	}
}

func TestNewRejectsMissingDependencies(t *testing.T) {
	cases := map[string]func(*server.Dependencies){
		"nil clients":      func(d *server.Dependencies) { d.Clients = nil },
		"nil transactions": func(d *server.Dependencies) { d.Transactions = nil },
		"nil grants":       func(d *server.Dependencies) { d.Grants = nil },
		"nil replay":       func(d *server.Dependencies) { d.Replay = nil },
		"nil client keys":  func(d *server.Dependencies) { d.ClientKeys = nil },
		"nil keys":         func(d *server.Dependencies) { d.Keys = nil },
		"nil clock":        func(d *server.Dependencies) { d.Clock = nil },
		"nil random":       func(d *server.Dependencies) { d.Random = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			deps := validDependencies()
			mutate(&deps)
			if _, err := server.New(validConfig(t), deps); err == nil {
				t.Fatalf("New(%s) = nil error, want error", name)
			}
		})
	}
}

func TestNewRequiresJARMConfigUnderMessageSigning(t *testing.T) {
	cfg := validConfig(t)
	cfg.Profile = server.ProfileFAPISecurityWithMessageSigning
	deps := validDependencies()

	if _, err := server.New(cfg, deps); err == nil {
		t.Fatalf("New(message signing, no jarm alg/lifetime) = nil error, want error")
	}

	cfg.Algorithms.JARM = fapi.ES256
	if _, err := server.New(cfg, deps); err == nil {
		t.Fatalf("New(message signing, no jarm lifetime) = nil error, want error")
	}

	cfg.Limits.JARMResponseLifetime = time.Minute
	if _, err := server.New(cfg, deps); err != nil {
		t.Fatalf("New(message signing, fully configured): %v", err)
	}
}

func TestNewRequiresAuditUnderProduction(t *testing.T) {
	cfg := validConfig(t)
	cfg.Assurance = server.AssuranceProduction
	deps := validDependencies()

	if _, err := server.New(cfg, deps); err == nil {
		t.Fatalf("New(production, no audit) = nil error, want error")
	}

	deps.Audit = &fakeAuditSink{}
	if _, err := server.New(cfg, deps); err != nil {
		t.Fatalf("New(production, with audit): %v", err)
	}
}

// bareReplayStore implements storage.ReplayStore but not
// storage.StoreAssurance at all, for testing that AssuranceProduction
// rejects a store that never declared its capabilities, rather than
// assuming an undeclared store is adequate.
type bareReplayStore struct{}

func (bareReplayStore) UseOnce(context.Context, storage.ReplayUse) error { return nil }

// capReplayStore implements storage.StoreAssurance with caller-chosen
// capabilities, for testing that AssuranceProduction actually inspects
// the declared values rather than merely requiring the method to exist.
type capReplayStore struct {
	bareReplayStore
	caps storage.Capabilities
}

func (s capReplayStore) Capabilities() storage.Capabilities { return s.caps }

func TestNewRejectsStoreWithoutStoreAssuranceUnderProduction(t *testing.T) {
	cfg := validConfig(t)
	cfg.Assurance = server.AssuranceProduction
	deps := validDependencies()
	deps.Audit = &fakeAuditSink{}
	deps.Replay = bareReplayStore{}

	if _, err := server.New(cfg, deps); err == nil {
		t.Fatalf("New(production, replay store without StoreAssurance) = nil error, want error")
	}
}

func TestNewRejectsNonDurableStoreUnderProduction(t *testing.T) {
	cfg := validConfig(t)
	cfg.Assurance = server.AssuranceProduction
	deps := validDependencies()
	deps.Audit = &fakeAuditSink{}
	deps.Replay = capReplayStore{caps: storage.Capabilities{Durable: false, AtomicConsume: true}}

	if _, err := server.New(cfg, deps); err == nil {
		t.Fatalf("New(production, non-durable replay store) = nil error, want error")
	}
}

func TestNewRejectsStoreWithoutAtomicConsumeUnderProduction(t *testing.T) {
	cfg := validConfig(t)
	cfg.Assurance = server.AssuranceProduction
	deps := validDependencies()
	deps.Audit = &fakeAuditSink{}
	deps.Replay = capReplayStore{caps: storage.Capabilities{Durable: true, AtomicConsume: false}}

	if _, err := server.New(cfg, deps); err == nil {
		t.Fatalf("New(production, replay store without AtomicConsume) = nil error, want error")
	}
}

func TestNewAcceptsAdequateStoreCapabilitiesUnderProduction(t *testing.T) {
	cfg := validConfig(t)
	cfg.Assurance = server.AssuranceProduction
	deps := validDependencies()
	deps.Audit = &fakeAuditSink{}
	deps.Replay = capReplayStore{caps: storage.Capabilities{Durable: true, AtomicConsume: true}}

	if _, err := server.New(cfg, deps); err != nil {
		t.Fatalf("New(production, adequate replay store): %v", err)
	}
}

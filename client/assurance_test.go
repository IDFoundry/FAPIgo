package client_test

import (
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// assuringSessionStore wraps fakeSessionStore with a self-asserted
// storage.StoreAssurance declaration, for tests that need a session
// store AssuranceProduction actually accepts.
type assuringSessionStore struct {
	*fakeSessionStore
	caps storage.Capabilities
}

func (s assuringSessionStore) Capabilities() storage.Capabilities { return s.caps }

// TestNewAcceptsDevelopmentAssuranceWithPlainSessionStore confirms
// AssuranceDevelopment asks no StoreAssurance question at all — the
// same session store every other client test in this package already
// relies on continues to work.
func TestNewAcceptsDevelopmentAssuranceWithPlainSessionStore(t *testing.T) {
	cfg := validConfig(t)
	cfg.Assurance = client.AssuranceDevelopment
	deps := validDependencies(t)
	deps.Sessions = newFakeSessionStore() // does not implement storage.StoreAssurance

	if _, err := client.New(cfg, deps); err != nil {
		t.Fatalf("New(AssuranceDevelopment, plain session store): %v", err)
	}
}

// TestNewRejectsProductionAssuranceWithoutStoreAssuranceDeclaration
// covers the core of this gate: under AssuranceProduction, a session
// store that doesn't implement storage.StoreAssurance at all is
// rejected rather than assumed adequate — mirroring
// server.AssuranceProduction's identical rule for its own stores.
func TestNewRejectsProductionAssuranceWithoutStoreAssuranceDeclaration(t *testing.T) {
	cfg := validConfig(t)
	cfg.Assurance = client.AssuranceProduction
	deps := validDependencies(t)
	deps.Sessions = newFakeSessionStore()

	if _, err := client.New(cfg, deps); err == nil {
		t.Fatal("New(AssuranceProduction, session store without StoreAssurance) = nil error, want error")
	}
}

// TestNewRejectsProductionAssuranceWhenSessionStoreNotDurable covers
// the Durable half of the declared-capabilities check.
func TestNewRejectsProductionAssuranceWhenSessionStoreNotDurable(t *testing.T) {
	cfg := validConfig(t)
	cfg.Assurance = client.AssuranceProduction
	deps := validDependencies(t)
	deps.Sessions = assuringSessionStore{
		fakeSessionStore: newFakeSessionStore(),
		caps:             storage.Capabilities{Durable: false, AtomicConsume: true},
	}

	if _, err := client.New(cfg, deps); err == nil {
		t.Fatal("New(AssuranceProduction, non-durable session store) = nil error, want error")
	}
}

// TestNewRejectsProductionAssuranceWhenSessionStoreNotAtomicConsume
// covers the AtomicConsume half — SessionStore.Consume is a
// single-use check-and-retire operation, the same category
// server.AssuranceProduction already requires AtomicConsume for.
func TestNewRejectsProductionAssuranceWhenSessionStoreNotAtomicConsume(t *testing.T) {
	cfg := validConfig(t)
	cfg.Assurance = client.AssuranceProduction
	deps := validDependencies(t)
	deps.Sessions = assuringSessionStore{
		fakeSessionStore: newFakeSessionStore(),
		caps:             storage.Capabilities{Durable: true, AtomicConsume: false},
	}

	if _, err := client.New(cfg, deps); err == nil {
		t.Fatal("New(AssuranceProduction, non-atomic-consume session store) = nil error, want error")
	}
}

// TestNewAcceptsProductionAssuranceWithFullyDeclaredSessionStore is
// the positive case: a session store declaring both required
// capabilities is accepted.
func TestNewAcceptsProductionAssuranceWithFullyDeclaredSessionStore(t *testing.T) {
	cfg := validConfig(t)
	cfg.Assurance = client.AssuranceProduction
	deps := validDependencies(t)
	deps.Sessions = assuringSessionStore{
		fakeSessionStore: newFakeSessionStore(),
		caps:             storage.Capabilities{Durable: true, AtomicConsume: true},
	}

	if _, err := client.New(cfg, deps); err != nil {
		t.Fatalf("New(AssuranceProduction, fully-declared session store): %v", err)
	}
}

// TestNewRejectsMemstoreSessionStoreUnderProductionAssurance is the
// concrete, real-world instance of this gate:
// memstore.NewSessionStore() — the obvious first choice for a new
// integration, and explicitly documented as non-durable and
// unbounded — is refused under AssuranceProduction, the same way
// server.New already refuses every memstore type for its own stores.
func TestNewRejectsMemstoreSessionStoreUnderProductionAssurance(t *testing.T) {
	cfg := validConfig(t)
	cfg.Assurance = client.AssuranceProduction
	deps := validDependencies(t)
	deps.Sessions = memstore.NewSessionStore()

	if _, err := client.New(cfg, deps); err == nil {
		t.Fatal("New(AssuranceProduction, memstore.NewSessionStore()) = nil error, want error")
	}
}

// TestNewSkipsSessionAssuranceCheckWhenSessionsNotConfigured confirms
// the gate only ever applies when Sessions is actually required
// (Endpoints.Authorization set) — a CIBA-only or client_credentials-only
// Config under AssuranceProduction with no Sessions dependency at all
// constructs successfully.
func TestNewSkipsSessionAssuranceCheckWhenSessionsNotConfigured(t *testing.T) {
	cfg := validConfig(t)
	cfg.Assurance = client.AssuranceProduction
	cfg.Endpoints.Authorization = fapi.URL{}
	cfg.Endpoints.PushedAuthorizationRequest = fapi.URL{}
	cfg.RedirectURI = ""

	deps := validDependencies(t)
	deps.Sessions = nil

	if _, err := client.New(cfg, deps); err != nil {
		t.Fatalf("New(AssuranceProduction, no browser flow, no Sessions dependency): %v", err)
	}
}

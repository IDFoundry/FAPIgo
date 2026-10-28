package client_test

import (
	"crypto/ecdh"
	"crypto/rand"
	"github.com/idfoundry/fapigo/keys/ephemeral"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/keys"
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

// assuringIssuerKeySource wraps fakeIssuerKeySource with an overridden
// keys.KeySourceAssurance declaration, for tests that need to control
// exactly what LiveFetchHardened value AssuranceProduction sees —
// fakeIssuerKeySource itself already always declares true (see its own
// doc comment), so this type exists specifically for the false case.
type assuringIssuerKeySource struct {
	*fakeIssuerKeySource
	caps keys.KeySourceCapabilities
}

func (s assuringIssuerKeySource) Capabilities() keys.KeySourceCapabilities { return s.caps }

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
	asProduction(&cfg)
	cfg.AuthorizationResponseIssPolicy = client.RequireAuthorizationResponseIss
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
	asProduction(&cfg)
	cfg.AuthorizationResponseIssPolicy = client.RequireAuthorizationResponseIss
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
	asProduction(&cfg)
	cfg.AuthorizationResponseIssPolicy = client.RequireAuthorizationResponseIss
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
	asProduction(&cfg)
	cfg.AuthorizationResponseIssPolicy = client.RequireAuthorizationResponseIss
	deps := validDependencies(t)
	deps.HTTP = hardenedHTTPClient(t, fapihttp.RecommendedTransportConfig())
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
	asProduction(&cfg)
	cfg.AuthorizationResponseIssPolicy = client.RequireAuthorizationResponseIss
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
	asProduction(&cfg)
	cfg.AuthorizationResponseIssPolicy = client.RequireAuthorizationResponseIss
	cfg.Endpoints.Authorization = fapi.URL{}
	cfg.Endpoints.PushedAuthorizationRequest = fapi.URL{}
	cfg.RedirectURI = ""

	deps := validDependencies(t)
	deps.HTTP = hardenedHTTPClient(t, fapihttp.RecommendedTransportConfig())
	deps.Sessions = nil

	if _, err := client.New(cfg, deps); err != nil {
		t.Fatalf("New(AssuranceProduction, no browser flow, no Sessions dependency): %v", err)
	}
}

// TestNewAcceptsDevelopmentAssuranceWithPlainIssuerKeySource confirms
// AssuranceDevelopment asks no keys.KeySourceAssurance question either
// — emptyIssuerKeySource (declares nothing) still works.
func TestNewAcceptsDevelopmentAssuranceWithPlainIssuerKeySource(t *testing.T) {
	cfg := validConfig(t)
	cfg.Assurance = client.AssuranceDevelopment
	deps := validDependencies(t)
	deps.IssuerKeys = emptyIssuerKeySource{}

	if _, err := client.New(cfg, deps); err != nil {
		t.Fatalf("New(AssuranceDevelopment, plain issuer key source): %v", err)
	}
}

// TestNewRejectsProductionAssuranceWithoutKeySourceAssuranceDeclaration
// covers the core of the gate for Dependencies.IssuerKeys, mirroring
// TestNewRejectsProductionAssuranceWithoutStoreAssuranceDeclaration for
// Sessions: an IssuerKeySource that doesn't implement
// keys.KeySourceAssurance at all is rejected rather than assumed
// adequate.
func TestNewRejectsProductionAssuranceWithoutKeySourceAssuranceDeclaration(t *testing.T) {
	cfg := validConfig(t)
	asProduction(&cfg)
	cfg.AuthorizationResponseIssPolicy = client.RequireAuthorizationResponseIss
	deps := validDependencies(t)
	deps.IssuerKeys = emptyIssuerKeySource{}
	// Sessions has its own, independent AssuranceProduction gate — satisfy
	// it too here so a Sessions failure can't stand in for (and mask a
	// missing) IssuerKeys failure, the way it did before this fix: an
	// err==nil check alone can't tell which dependency actually failed.
	deps.Sessions = assuringSessionStore{
		fakeSessionStore: newFakeSessionStore(),
		caps:             storage.Capabilities{Durable: true, AtomicConsume: true},
	}

	_, err := client.New(cfg, deps)
	if err == nil {
		t.Fatal("New(AssuranceProduction, issuer key source without KeySourceAssurance) = nil error, want error")
	}
	if !strings.Contains(err.Error(), "issuer_keys") {
		t.Fatalf("New(...) error = %q, want it to mention issuer_keys", err)
	}
}

// TestNewRejectsProductionAssuranceWhenIssuerKeySourceNotLiveFetchHardened
// covers the declared-but-insufficient case.
func TestNewRejectsProductionAssuranceWhenIssuerKeySourceNotLiveFetchHardened(t *testing.T) {
	cfg := validConfig(t)
	asProduction(&cfg)
	cfg.AuthorizationResponseIssPolicy = client.RequireAuthorizationResponseIss
	deps := validDependencies(t)
	deps.IssuerKeys = assuringIssuerKeySource{
		fakeIssuerKeySource: deps.IssuerKeys.(*fakeIssuerKeySource),
		caps:                keys.KeySourceCapabilities{LiveFetchHardened: false},
	}
	deps.Sessions = assuringSessionStore{
		fakeSessionStore: newFakeSessionStore(),
		caps:             storage.Capabilities{Durable: true, AtomicConsume: true},
	}

	_, err := client.New(cfg, deps)
	if err == nil {
		t.Fatal("New(AssuranceProduction, issuer key source declaring LiveFetchHardened=false) = nil error, want error")
	}
	if !strings.Contains(err.Error(), "issuer_keys") {
		t.Fatalf("New(...) error = %q, want it to mention issuer_keys", err)
	}
}

// TestNewAcceptsProductionAssuranceWithLiveFetchHardenedIssuerKeySource
// is the positive case: an issuer key source declaring
// LiveFetchHardened is accepted.
func TestNewAcceptsProductionAssuranceWithLiveFetchHardenedIssuerKeySource(t *testing.T) {
	cfg := validConfig(t)
	asProduction(&cfg)
	cfg.AuthorizationResponseIssPolicy = client.RequireAuthorizationResponseIss
	deps := validDependencies(t)
	deps.HTTP = hardenedHTTPClient(t, fapihttp.RecommendedTransportConfig())
	deps.IssuerKeys = assuringIssuerKeySource{
		fakeIssuerKeySource: deps.IssuerKeys.(*fakeIssuerKeySource),
		caps:                keys.KeySourceCapabilities{LiveFetchHardened: true},
	}
	// Sessions has its own, independent AssuranceProduction gate (see
	// TestNewAcceptsProductionAssuranceWithFullyDeclaredSessionStore) —
	// satisfy it too here so this test isolates the IssuerKeys check.
	deps.Sessions = assuringSessionStore{
		fakeSessionStore: newFakeSessionStore(),
		caps:             storage.Capabilities{Durable: true, AtomicConsume: true},
	}

	if _, err := client.New(cfg, deps); err != nil {
		t.Fatalf("New(AssuranceProduction, LiveFetchHardened issuer key source): %v", err)
	}
}

// asProduction sets cfg's assurance to AssuranceProduction, with the
// MaxClockSkew it requires (validConfig's 5 seconds is below it).
func asProduction(cfg *client.Config) {
	cfg.Assurance = client.AssuranceProduction
	cfg.Limits.MaxClockSkew = 10 * time.Second
}

// productionDeps is validDependencies with every non-key AssuranceProduction
// declaration satisfied, so a test isolates the key custody checks.
func productionDeps(t *testing.T) client.Dependencies {
	t.Helper()
	deps := validDependencies(t)
	deps.IssuerKeys = assuringIssuerKeySource{
		fakeIssuerKeySource: deps.IssuerKeys.(*fakeIssuerKeySource),
		caps:                keys.KeySourceCapabilities{LiveFetchHardened: true},
	}
	deps.Sessions = assuringSessionStore{
		fakeSessionStore: newFakeSessionStore(),
		caps:             storage.Capabilities{Durable: true, AtomicConsume: true},
	}
	deps.HTTP = hardenedHTTPClient(t, fapihttp.RecommendedTransportConfig())
	return deps
}

// hardenedHTTPClient is fapihttp.NewClient's client for cfg, the only
// kind AssuranceProduction accepts as Dependencies.HTTP.
func hardenedHTTPClient(t *testing.T, cfg fapihttp.TransportConfig) *http.Client {
	t.Helper()
	c, err := fapihttp.NewClient(cfg)
	if err != nil {
		t.Fatalf("fapihttp.NewClient: %v", err)
	}
	return c
}

// undeclaredClientKeys has the fake key manager's methods but not its
// test-only KeyCustody.
type undeclaredClientKeys struct{ keys.KeyManager }

func TestNewProductionRequiresClientKeyCustody(t *testing.T) {
	cfg := validConfig(t)
	asProduction(&cfg)
	cfg.AuthorizationResponseIssPolicy = client.RequireAuthorizationResponseIss

	deps := productionDeps(t)
	if _, err := client.New(cfg, deps); err != nil {
		t.Fatalf("New(production, declared keys): %v", err)
	}

	deps = productionDeps(t)
	deps.Keys = undeclaredClientKeys{deps.Keys}
	if _, err := client.New(cfg, deps); err == nil || !strings.Contains(err.Error(), "keys must implement keys.KeyCustodyAssurance") {
		t.Fatalf("New(production, undeclared keys) error = %v, want a key custody error", err)
	}

	ephemeralKeys, err := ephemeral.NewKeyManager(map[keys.SigningPurpose]fapi.SignatureAlgorithm{keys.ClientAuthentication: fapi.ES256, keys.DPoPProofSigning: fapi.ES256})
	if err != nil {
		t.Fatalf("ephemeral.NewKeyManager: %v", err)
	}
	deps = productionDeps(t)
	deps.Keys = ephemeralKeys
	if _, err := client.New(cfg, deps); err == nil || !strings.Contains(err.Error(), "keys must implement keys.KeyCustodyAssurance") {
		t.Fatalf("New(production, ephemeral keys) error = %v, want a key custody error", err)
	}
}

func TestNewProductionRequiresDecryptionKeyCustody(t *testing.T) {
	cfg := validConfig(t)
	asProduction(&cfg)
	cfg.AuthorizationResponseIssPolicy = client.RequireAuthorizationResponseIss
	cfg.Algorithms.IDTokenKeyManagement = fapi.ECDHESA256KW
	cfg.Algorithms.IDTokenContentEncryption = fapi.A256GCM

	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	backend, err := keys.NewInMemoryECDH(priv, "enc-1")
	if err != nil {
		t.Fatalf("NewInMemoryECDH: %v", err)
	}
	undeclared, err := keys.NewSingleKeyDecrypter(backend)
	if err != nil {
		t.Fatalf("NewSingleKeyDecrypter: %v", err)
	}
	declared, err := keys.NewSingleKeyDecrypter(backend, keys.DeclareCustody(keys.KeyCustody{Durable: true}))
	if err != nil {
		t.Fatalf("NewSingleKeyDecrypter: %v", err)
	}

	deps := productionDeps(t)
	deps.Decryption = undeclared
	if _, err := client.New(cfg, deps); err == nil || !strings.Contains(err.Error(), "decryption must implement keys.KeyCustodyAssurance") {
		t.Fatalf("New(production, undeclared decryption) error = %v, want a key custody error", err)
	}
	deps = productionDeps(t)
	deps.Decryption = declared
	if _, err := client.New(cfg, deps); err != nil {
		t.Fatalf("New(production, declared decryption): %v", err)
	}
}

// TestNewReportsEveryProductionRefusal: New reports every dependency
// production assurance refuses, not just the first.
func TestNewReportsEveryProductionRefusal(t *testing.T) {
	cfg := validConfig(t)
	asProduction(&cfg)
	cfg.AuthorizationResponseIssPolicy = client.RequireAuthorizationResponseIss
	deps := validDependencies(t) // an undeclared sessions store
	deps.Keys = undeclaredClientKeys{deps.Keys}
	deps.Random = io.MultiReader(rand.Reader) // a wrapper, not crypto/rand.Reader itself

	_, err := client.New(cfg, deps)
	if err == nil {
		t.Fatal("New(production, three refusals) = nil error, want error")
	}
	for _, want := range []string{
		"sessions must implement storage.StoreAssurance",
		"keys must implement keys.KeyCustodyAssurance",
		"random must be crypto/rand.Reader itself",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("New error = %q, want it to contain %q", err, want)
		}
	}
}

// TestNewProductionRefusesDeviceLocalBindingOverASharedStore:
// CallbackBindingDeviceLocalStore finds a session by the callback's
// state alone, which is safe only in a native app's own store. Production
// accepts it only for a native app's redirect URI (loopback http to an
// IP literal, or a private-use scheme) over a store that doesn't declare
// CrossInstanceConsistent: a web client's https redirect means a
// server-side store, single-instance or not, where it brings login CSRF
// back.
func TestNewProductionRefusesDeviceLocalBindingOverASharedStore(t *testing.T) {
	shared := storage.Capabilities{Durable: true, AtomicConsume: true, CrossInstanceConsistent: true}
	device := storage.Capabilities{Durable: true, AtomicConsume: true}
	const (
		web        = "https://client.example/callback"
		loopback   = "http://127.0.0.1/callback"
		loopback6  = "http://[::1]:8080/callback"
		privateUse = "com.example.wallet:/callback"
	)
	for _, tc := range []struct {
		name     string
		binding  client.CallbackBinding
		redirect string
		caps     storage.Capabilities
		refused  bool
	}{
		{"device-local, loopback, device store", client.CallbackBindingDeviceLocalStore, loopback, device, false},
		{"device-local, IPv6 loopback, device store", client.CallbackBindingDeviceLocalStore, loopback6, device, false},
		{"device-local, private-use scheme, device store", client.CallbackBindingDeviceLocalStore, privateUse, device, false},
		{"device-local, web redirect, single-instance store", client.CallbackBindingDeviceLocalStore, web, device, true},
		{"device-local, private-use scheme, shared store", client.CallbackBindingDeviceLocalStore, privateUse, shared, true},
		{"device-local, web redirect, shared store", client.CallbackBindingDeviceLocalStore, web, shared, true},
		{"session handle, web redirect, shared store", client.CallbackBindingSessionHandle, web, shared, false},
		{"session handle, web redirect, single-instance store", client.CallbackBindingSessionHandle, web, device, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig(t)
			asProduction(&cfg)
			cfg.AuthorizationResponseIssPolicy = client.RequireAuthorizationResponseIss
			cfg.CallbackBinding = tc.binding
			cfg.RedirectURI = tc.redirect
			deps := productionDeps(t)
			deps.Sessions = assuringSessionStore{fakeSessionStore: newFakeSessionStore(), caps: tc.caps}
			_, err := client.New(cfg, deps)
			if refused := err != nil && strings.Contains(err.Error(), "CallbackBindingDeviceLocalStore"); refused != tc.refused || (err != nil && !refused) {
				t.Fatalf("New = %v, want refused %v", err, tc.refused)
			}
		})
	}
}

// TestNewProductionRequiresAuthorizationResponseIss: FAPI 2.0 has the
// authorization server send iss (RFC 9207) and the client check it, so
// production refuses the tolerant policy; development still allows it.
func TestNewProductionRequiresAuthorizationResponseIss(t *testing.T) {
	cfg := validConfig(t)
	asProduction(&cfg)
	cfg.AuthorizationResponseIssPolicy = client.TolerateAbsentAuthorizationResponseIss
	if _, err := client.New(cfg, productionDeps(t)); err == nil || !strings.Contains(err.Error(), "TolerateAbsentAuthorizationResponseIss") {
		t.Fatalf("New(production, tolerate absent iss) = %v, want refused", err)
	}
	cfg.AuthorizationResponseIssPolicy = client.RequireAuthorizationResponseIss
	if _, err := client.New(cfg, productionDeps(t)); err != nil {
		t.Fatalf("New(production, require iss) = %v", err)
	}
	cfg = validConfig(t)
	cfg.AuthorizationResponseIssPolicy = client.TolerateAbsentAuthorizationResponseIss
	if _, err := client.New(cfg, validDependencies(t)); err != nil {
		t.Fatalf("New(development, tolerate absent iss) = %v", err)
	}
}

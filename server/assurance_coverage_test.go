package server_test

import (
	"context"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// This file covers AssuranceProduction's own coverage of the three
// stores it previously missed entirely (Dependencies.Nonces, the
// opaque-token store nested inside Dependencies.AccessTokens, and
// Dependencies.Revocation), plus Config.HorizontallyScaled's own
// CrossInstanceConsistent requirement — see checkStoreAssurance's own
// doc comment. Mirrors the existing bareReplayStore/capReplayStore
// pattern in server_test.go for each store type.
//
// It also adds a negative test for each of the pre-existing
// checkStoreAssurance call sites (clients, transactions, grants,
// backchannel) that this change touched — by adding the new scaled
// argument — without previously having its own failure-path test;
// validDependencies' fakes for those stores already declare adequate
// capabilities, so nothing before this change exercised the "store
// implements the domain interface but not storage.StoreAssurance"
// branch for them. Each bare*Store embeds the plain storage interface
// so it satisfies that interface by delegation (its methods are never
// actually called — checkStoreAssurance only type-asserts for
// storage.StoreAssurance) while genuinely lacking a Capabilities
// method, unlike embedding one of validDependencies' own fakes would.

type bareClientRepository struct{ storage.ClientRepository }

type bareTransactionStore struct{ storage.TransactionStore }

type bareGrantStore struct{ storage.GrantStore }

type bareBackchannelAuthenticationStore struct {
	storage.BackchannelAuthenticationStore
}

func TestNewRejectsClientsStoreWithoutStoreAssuranceUnderProduction(t *testing.T) {
	cfg := validConfig(t)
	cfg.Assurance = server.AssuranceProduction
	deps := validDependencies()
	deps.Audit = &fakeAuditSink{}
	deps.Clients = bareClientRepository{}

	if _, err := server.New(cfg, deps); err == nil {
		t.Fatal("New(production, clients store without StoreAssurance) = nil error, want error")
	}
}

func TestNewRejectsTransactionsStoreWithoutStoreAssuranceUnderProduction(t *testing.T) {
	cfg := validConfig(t)
	cfg.Assurance = server.AssuranceProduction
	deps := validDependencies()
	deps.Audit = &fakeAuditSink{}
	deps.Transactions = bareTransactionStore{}

	if _, err := server.New(cfg, deps); err == nil {
		t.Fatal("New(production, transactions store without StoreAssurance) = nil error, want error")
	}
}

func TestNewRejectsGrantsStoreWithoutStoreAssuranceUnderProduction(t *testing.T) {
	cfg := validConfig(t)
	cfg.Assurance = server.AssuranceProduction
	deps := validDependencies()
	deps.Audit = &fakeAuditSink{}
	deps.Grants = bareGrantStore{}

	if _, err := server.New(cfg, deps); err == nil {
		t.Fatal("New(production, grants store without StoreAssurance) = nil error, want error")
	}
}

func TestNewRejectsBackchannelStoreWithoutStoreAssuranceUnderProduction(t *testing.T) {
	cfg := validConfig(t)
	cfg.Assurance = server.AssuranceProduction
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
	deps.Backchannel = bareBackchannelAuthenticationStore{}
	deps.BackchannelNotifier = server.NoBackchannelNotifications{}

	if _, err := server.New(cfg, deps); err == nil {
		t.Fatal("New(production, backchannel store without StoreAssurance) = nil error, want error")
	}
}

type bareNonceStore struct{}

func (bareNonceStore) Issue(context.Context, storage.NonceIssuance) error { return nil }
func (bareNonceStore) Consume(context.Context, storage.NonceConsumption) (storage.NonceRecord, error) {
	return storage.NonceRecord{}, nil
}

type capNonceStore struct {
	bareNonceStore
	caps storage.Capabilities
}

func (s capNonceStore) Capabilities() storage.Capabilities { return s.caps }

func TestNewRejectsNonceStoreWithoutStoreAssuranceUnderProduction(t *testing.T) {
	cfg := validConfig(t)
	cfg.Assurance = server.AssuranceProduction
	deps := validDependencies()
	deps.Audit = &fakeAuditSink{}
	deps.Nonces = bareNonceStore{}
	cfg.Limits.DPoPNonceLifetime = time.Minute

	if _, err := server.New(cfg, deps); err == nil {
		t.Fatal("New(production, nonce store without StoreAssurance) = nil error, want error")
	}
}

func TestNewAcceptsAdequateNonceStoreUnderProduction(t *testing.T) {
	cfg := validConfig(t)
	cfg.Assurance = server.AssuranceProduction
	deps := validDependencies()
	deps.Audit = &fakeAuditSink{}
	deps.Nonces = capNonceStore{caps: storage.Capabilities{Durable: true, AtomicConsume: true}}
	cfg.Limits.DPoPNonceLifetime = time.Minute

	if _, err := server.New(cfg, deps); err != nil {
		t.Fatalf("New(production, adequate nonce store): %v", err)
	}
}

func TestNewSkipsNonceCheckWhenNoncesNotConfigured(t *testing.T) {
	cfg := validConfig(t)
	cfg.Assurance = server.AssuranceProduction
	deps := validDependencies()
	deps.Audit = &fakeAuditSink{}
	deps.Nonces = nil // genuinely optional — DPoP nonce-challenge support disabled

	if _, err := server.New(cfg, deps); err != nil {
		t.Fatalf("New(production, no nonce store configured): %v", err)
	}
}

type bareAccessTokenStore struct{}

func (bareAccessTokenStore) CreateAccessToken(context.Context, storage.NewAccessToken) error {
	return nil
}
func (bareAccessTokenStore) LookupAccessToken(context.Context, storage.AccessTokenLookup) (storage.LookedUpAccessToken, error) {
	return storage.LookedUpAccessToken{}, nil
}

type capAccessTokenStore struct {
	bareAccessTokenStore
	caps storage.Capabilities
}

func (s capAccessTokenStore) Capabilities() storage.Capabilities { return s.caps }

func TestNewRejectsOpaqueAccessTokenStoreWithoutStoreAssuranceUnderProduction(t *testing.T) {
	cfg := validConfig(t)
	cfg.Assurance = server.AssuranceProduction
	deps := validDependencies()
	deps.Audit = &fakeAuditSink{}
	deps.AccessTokens = server.OpaqueAccessTokens{Store: bareAccessTokenStore{}}

	if _, err := server.New(cfg, deps); err == nil {
		t.Fatal("New(production, opaque access-token store without StoreAssurance) = nil error, want error")
	}
}

func TestNewAcceptsAdequateOpaqueAccessTokenStoreUnderProduction(t *testing.T) {
	cfg := validConfig(t)
	cfg.Assurance = server.AssuranceProduction
	deps := validDependencies()
	deps.Audit = &fakeAuditSink{}
	deps.AccessTokens = server.OpaqueAccessTokens{
		Store: capAccessTokenStore{caps: storage.Capabilities{Durable: true}},
	}

	if _, err := server.New(cfg, deps); err != nil {
		t.Fatalf("New(production, adequate opaque access-token store): %v", err)
	}
}

func TestNewSkipsAccessTokenCheckForJWTAccessTokens(t *testing.T) {
	cfg := validConfig(t)
	cfg.Assurance = server.AssuranceProduction
	deps := validDependencies() // AccessTokens: server.JWTAccessTokens{...} by default — no separate store
	deps.Audit = &fakeAuditSink{}

	if _, err := server.New(cfg, deps); err != nil {
		t.Fatalf("New(production, JWTAccessTokens issuer): %v", err)
	}
}

type capRevocationSink struct {
	caps storage.Capabilities
}

func (capRevocationSink) Revoke(context.Context, string, time.Time) error { return nil }
func (s capRevocationSink) Capabilities() storage.Capabilities            { return s.caps }

type bareRevocationSink struct{}

func (bareRevocationSink) Revoke(context.Context, string, time.Time) error { return nil }

func TestNewRejectsRevocationWithoutStoreAssuranceUnderProduction(t *testing.T) {
	cfg := validConfig(t)
	cfg.Assurance = server.AssuranceProduction
	deps := validDependencies()
	deps.Audit = &fakeAuditSink{}
	deps.Revocation = bareRevocationSink{}

	if _, err := server.New(cfg, deps); err == nil {
		t.Fatal("New(production, revocation sink without StoreAssurance) = nil error, want error")
	}
}

func TestNewAcceptsAdequateRevocationUnderProduction(t *testing.T) {
	cfg := validConfig(t)
	cfg.Assurance = server.AssuranceProduction
	deps := validDependencies()
	deps.Audit = &fakeAuditSink{}
	deps.Revocation = capRevocationSink{caps: storage.Capabilities{Durable: true}}

	if _, err := server.New(cfg, deps); err != nil {
		t.Fatalf("New(production, adequate revocation sink): %v", err)
	}
}

func TestNewSkipsRevocationCheckWhenDeclined(t *testing.T) {
	cfg := validConfig(t)
	cfg.Assurance = server.AssuranceProduction
	deps := validDependencies() // Revocation: server.NoRevocation{} by default
	deps.Audit = &fakeAuditSink{}

	if _, err := server.New(cfg, deps); err != nil {
		t.Fatalf("New(production, NoRevocation{}): %v", err)
	}
}

func TestNewRequiresCrossInstanceConsistentWhenHorizontallyScaled(t *testing.T) {
	cfg := validConfig(t)
	cfg.Assurance = server.AssuranceProduction
	cfg.HorizontallyScaled = true
	deps := validDependencies()
	deps.Audit = &fakeAuditSink{}
	deps.Replay = capReplayStore{caps: storage.Capabilities{Durable: true, AtomicConsume: true, CrossInstanceConsistent: false}}

	if _, err := server.New(cfg, deps); err == nil {
		t.Fatal("New(production, horizontally scaled, replay store not cross-instance consistent) = nil error, want error")
	}
}

func TestNewAcceptsCrossInstanceConsistentStoreWhenHorizontallyScaled(t *testing.T) {
	cfg := validConfig(t)
	cfg.Assurance = server.AssuranceProduction
	cfg.HorizontallyScaled = true
	deps := validDependencies()
	deps.Audit = &fakeAuditSink{}
	deps.Replay = capReplayStore{caps: storage.Capabilities{Durable: true, AtomicConsume: true, CrossInstanceConsistent: true}}

	if _, err := server.New(cfg, deps); err != nil {
		t.Fatalf("New(production, horizontally scaled, cross-instance consistent replay store): %v", err)
	}
}

func TestNewIgnoresCrossInstanceConsistentWhenNotHorizontallyScaled(t *testing.T) {
	cfg := validConfig(t)
	cfg.Assurance = server.AssuranceProduction
	cfg.HorizontallyScaled = false
	deps := validDependencies()
	deps.Audit = &fakeAuditSink{}
	deps.Replay = capReplayStore{caps: storage.Capabilities{Durable: true, AtomicConsume: true, CrossInstanceConsistent: false}}

	if _, err := server.New(cfg, deps); err != nil {
		t.Fatalf("New(production, not horizontally scaled, replay store not cross-instance consistent): %v", err)
	}
}

// bareClientKeySource/bareClientEncryptionKeySource embed the plain
// domain interface so each satisfies it by delegation (never actually
// called — checkKeySourceAssurance only type-asserts for
// keys.KeySourceAssurance) while genuinely lacking a Capabilities
// method, mirroring the bare*Store pattern above.
type bareClientKeySource struct{ keys.ClientKeySource }

type bareClientEncryptionKeySource struct{ keys.ClientEncryptionKeySource }

// capClientKeySource/capClientEncryptionKeySource declare an explicit
// keys.KeySourceCapabilities, for the declared-but-insufficient case.
type capClientKeySource struct {
	keys.ClientKeySource
	caps keys.KeySourceCapabilities
}

func (s capClientKeySource) Capabilities() keys.KeySourceCapabilities { return s.caps }

type capClientEncryptionKeySource struct {
	keys.ClientEncryptionKeySource
	caps keys.KeySourceCapabilities
}

func (s capClientEncryptionKeySource) Capabilities() keys.KeySourceCapabilities { return s.caps }

func TestNewRejectsClientKeysWithoutKeySourceAssuranceUnderProduction(t *testing.T) {
	cfg := validConfig(t)
	cfg.Assurance = server.AssuranceProduction
	deps := validDependencies()
	deps.Audit = &fakeAuditSink{}
	deps.ClientKeys = bareClientKeySource{}

	if _, err := server.New(cfg, deps); err == nil {
		t.Fatal("New(production, client keys without KeySourceAssurance) = nil error, want error")
	}
}

func TestNewRejectsClientKeysNotLiveFetchHardenedUnderProduction(t *testing.T) {
	cfg := validConfig(t)
	cfg.Assurance = server.AssuranceProduction
	deps := validDependencies()
	deps.Audit = &fakeAuditSink{}
	deps.ClientKeys = capClientKeySource{caps: keys.KeySourceCapabilities{LiveFetchHardened: false}}

	if _, err := server.New(cfg, deps); err == nil {
		t.Fatal("New(production, client keys declaring LiveFetchHardened=false) = nil error, want error")
	}
}

func TestNewAcceptsLiveFetchHardenedClientKeysUnderProduction(t *testing.T) {
	cfg := validConfig(t)
	cfg.Assurance = server.AssuranceProduction
	deps := validDependencies()
	deps.Audit = &fakeAuditSink{}
	deps.ClientKeys = capClientKeySource{caps: keys.KeySourceCapabilities{LiveFetchHardened: true}}

	if _, err := server.New(cfg, deps); err != nil {
		t.Fatalf("New(production, LiveFetchHardened client keys): %v", err)
	}
}

// TestNewSkipsClientEncryptionKeysAssuranceCheckWhenNotConfigured
// confirms the gate only applies when ClientEncryptionKeys is actually
// set — validDependencies() leaves it nil by default, and no encryption
// algorithm is configured here, so New never requires it at all.
func TestNewSkipsClientEncryptionKeysAssuranceCheckWhenNotConfigured(t *testing.T) {
	cfg := validConfig(t)
	cfg.Assurance = server.AssuranceProduction
	deps := validDependencies()
	deps.Audit = &fakeAuditSink{}

	if _, err := server.New(cfg, deps); err != nil {
		t.Fatalf("New(production, no client encryption keys configured): %v", err)
	}
}

func TestNewRejectsClientEncryptionKeysWithoutKeySourceAssuranceUnderProduction(t *testing.T) {
	cfg := validConfig(t)
	cfg.Assurance = server.AssuranceProduction
	cfg.Algorithms.IDTokenEncryptionKeyManagement = server.KeyManagementAlgorithmSet{fapi.RSAOAEP256}
	cfg.Algorithms.IDTokenEncryptionContentEncryption = server.ContentEncryptionAlgorithmSet{fapi.A256GCM}
	deps := validDependencies()
	deps.Audit = &fakeAuditSink{}
	deps.ClientEncryptionKeys = bareClientEncryptionKeySource{}

	if _, err := server.New(cfg, deps); err == nil {
		t.Fatal("New(production, client encryption keys without KeySourceAssurance) = nil error, want error")
	}
}

func TestNewAcceptsLiveFetchHardenedClientEncryptionKeysUnderProduction(t *testing.T) {
	cfg := validConfig(t)
	cfg.Assurance = server.AssuranceProduction
	cfg.Algorithms.IDTokenEncryptionKeyManagement = server.KeyManagementAlgorithmSet{fapi.RSAOAEP256}
	cfg.Algorithms.IDTokenEncryptionContentEncryption = server.ContentEncryptionAlgorithmSet{fapi.A256GCM}
	deps := validDependencies()
	deps.Audit = &fakeAuditSink{}
	deps.ClientEncryptionKeys = capClientEncryptionKeySource{caps: keys.KeySourceCapabilities{LiveFetchHardened: true}}

	if _, err := server.New(cfg, deps); err != nil {
		t.Fatalf("New(production, LiveFetchHardened client encryption keys): %v", err)
	}
}

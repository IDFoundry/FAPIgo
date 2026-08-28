package server_test

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// fakeClientEncryptionKeySource is the encryption-side counterpart of
// fakeClientKeySource (par_test.go), used only to exercise New's
// dependency cross-check — no test in this file resolves an actual key
// through it.
type fakeClientEncryptionKeySource struct{}

func (fakeClientEncryptionKeySource) ResolveEncryptionKeys(context.Context, keys.ClientEncryptionKeyRequest) (keys.ClientEncryptionKeySet, error) {
	return keys.ClientEncryptionKeySet{}, nil
}

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
		AccessTokens: server.JWTAccessTokens{Keys: &fakeKeyManager{}, Algorithm: fapi.ES256},
		Revocation:   server.NoRevocation{},
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

// TestNewJWTAccessTokensRejectsInvalid covers what
// TestNewRejectsInvalidConfig used to check directly against
// Config.Algorithms.AccessToken before that field and its validation
// moved into JWTAccessTokens itself (see server/accesstoken.go).
func TestNewJWTAccessTokensRejectsInvalid(t *testing.T) {
	if _, err := server.NewJWTAccessTokens(nil, fapi.ES256); err == nil {
		t.Fatalf("NewJWTAccessTokens(nil keys) = nil error, want error")
	}
	if _, err := server.NewJWTAccessTokens(&fakeKeyManager{}, 0); err == nil {
		t.Fatalf("NewJWTAccessTokens(invalid algorithm) = nil error, want error")
	}
}

// TestNewOpaqueAccessTokensRejectsInvalid — every existing test that
// uses OpaqueAccessTokens builds it as a bare struct literal
// (OpaqueAccessTokens{Store: store}), bypassing this validating
// constructor entirely, so its one check (reject a nil store) had
// never actually run.
func TestNewOpaqueAccessTokensRejectsInvalid(t *testing.T) {
	if _, err := server.NewOpaqueAccessTokens(nil); err == nil {
		t.Fatalf("NewOpaqueAccessTokens(nil store) = nil error, want error")
	}
}

func TestNewRejectsMissingDependencies(t *testing.T) {
	cases := map[string]func(*server.Dependencies){
		"nil clients":       func(d *server.Dependencies) { d.Clients = nil },
		"nil transactions":  func(d *server.Dependencies) { d.Transactions = nil },
		"nil grants":        func(d *server.Dependencies) { d.Grants = nil },
		"nil replay":        func(d *server.Dependencies) { d.Replay = nil },
		"nil client keys":   func(d *server.Dependencies) { d.ClientKeys = nil },
		"nil keys":          func(d *server.Dependencies) { d.Keys = nil },
		"nil access tokens": func(d *server.Dependencies) { d.AccessTokens = nil },
		"nil revocation":    func(d *server.Dependencies) { d.Revocation = nil },
		"nil clock":         func(d *server.Dependencies) { d.Clock = nil },
		"nil random":        func(d *server.Dependencies) { d.Random = nil },
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

// TestNewRejectsInvalidIDTokenEncryptionConfig exercises validateConfig's
// id_token_encryption_key_management/content_encryption checks in
// isolation: deps.ClientEncryptionKeys is always present here, so a
// rejection can only come from the config-level check under test, not
// from validateDependencies's separate cross-check (see
// TestNewRequiresClientEncryptionKeysWhenIDTokenEncryptionConfigured for
// that one).
func TestNewRejectsInvalidIDTokenEncryptionConfig(t *testing.T) {
	cases := map[string]func(*server.Config){
		"key mgmt without content enc": func(c *server.Config) {
			c.Algorithms.IDTokenEncryptionKeyManagement = server.KeyManagementAlgorithmSet{fapi.RSAOAEP256}
		},
		"content enc without key mgmt": func(c *server.Config) {
			c.Algorithms.IDTokenEncryptionContentEncryption = server.ContentEncryptionAlgorithmSet{fapi.A256GCM}
		},
		"invalid key mgmt alg": func(c *server.Config) {
			c.Algorithms.IDTokenEncryptionKeyManagement = server.KeyManagementAlgorithmSet{0}
			c.Algorithms.IDTokenEncryptionContentEncryption = server.ContentEncryptionAlgorithmSet{fapi.A256GCM}
		},
		"invalid content enc alg": func(c *server.Config) {
			c.Algorithms.IDTokenEncryptionKeyManagement = server.KeyManagementAlgorithmSet{fapi.RSAOAEP256}
			c.Algorithms.IDTokenEncryptionContentEncryption = server.ContentEncryptionAlgorithmSet{0}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := validConfig(t)
			mutate(&cfg)
			deps := validDependencies()
			deps.ClientEncryptionKeys = fakeClientEncryptionKeySource{}
			if _, err := server.New(cfg, deps); err == nil {
				t.Fatalf("New(%s) = nil error, want error", name)
			}
		})
	}
}

// TestNewAcceptsValidIDTokenEncryptionConfig confirms both algorithm sets
// set together, with a matching dependency, is accepted — the positive
// counterpart of TestNewRejectsInvalidIDTokenEncryptionConfig.
func TestNewAcceptsValidIDTokenEncryptionConfig(t *testing.T) {
	cfg := validConfig(t)
	cfg.Algorithms.IDTokenEncryptionKeyManagement = server.KeyManagementAlgorithmSet{fapi.RSAOAEP256}
	cfg.Algorithms.IDTokenEncryptionContentEncryption = server.ContentEncryptionAlgorithmSet{fapi.A256GCM}
	deps := validDependencies()
	deps.ClientEncryptionKeys = fakeClientEncryptionKeySource{}

	if _, err := server.New(cfg, deps); err != nil {
		t.Fatalf("New(valid id token encryption config): %v", err)
	}
}

// TestNewRequiresClientEncryptionKeysWhenIDTokenEncryptionConfigured covers
// Phase 5's cross-check: enabling ID token encryption server-wide is
// meaningless without something that can resolve a client's encryption
// key, so New must reject that combination the same way it already
// rejects, e.g., a nil ClientKeys with any configuration.
func TestNewRequiresClientEncryptionKeysWhenIDTokenEncryptionConfigured(t *testing.T) {
	cfg := validConfig(t)
	cfg.Algorithms.IDTokenEncryptionKeyManagement = server.KeyManagementAlgorithmSet{fapi.RSAOAEP256}
	cfg.Algorithms.IDTokenEncryptionContentEncryption = server.ContentEncryptionAlgorithmSet{fapi.A256GCM}
	deps := validDependencies()

	if _, err := server.New(cfg, deps); err == nil {
		t.Fatalf("New(id token encryption configured, no client encryption keys) = nil error, want error")
	}

	deps.ClientEncryptionKeys = fakeClientEncryptionKeySource{}
	if _, err := server.New(cfg, deps); err != nil {
		t.Fatalf("New(id token encryption configured, with client encryption keys): %v", err)
	}
}

// TestNewRejectsInvalidUserInfoConfig mirrors
// TestNewRejectsInvalidIDTokenEncryptionConfig for Algorithms.UserInfo/
// UserInfoEncryptionKeyManagement/UserInfoEncryptionContentEncryption —
// a separate, independent field trio, not a reuse of the ID token one.
func TestNewRejectsInvalidUserInfoConfig(t *testing.T) {
	cases := map[string]func(*server.Config){
		"invalid userinfo signing alg": func(c *server.Config) {
			c.Algorithms.UserInfo = fapi.SignatureAlgorithm(99)
		},
		"key mgmt without content enc": func(c *server.Config) {
			c.Algorithms.UserInfoEncryptionKeyManagement = server.KeyManagementAlgorithmSet{fapi.RSAOAEP256}
		},
		"content enc without key mgmt": func(c *server.Config) {
			c.Algorithms.UserInfoEncryptionContentEncryption = server.ContentEncryptionAlgorithmSet{fapi.A256GCM}
		},
		"invalid key mgmt alg": func(c *server.Config) {
			c.Algorithms.UserInfoEncryptionKeyManagement = server.KeyManagementAlgorithmSet{0}
			c.Algorithms.UserInfoEncryptionContentEncryption = server.ContentEncryptionAlgorithmSet{fapi.A256GCM}
		},
		"invalid content enc alg": func(c *server.Config) {
			c.Algorithms.UserInfoEncryptionKeyManagement = server.KeyManagementAlgorithmSet{fapi.RSAOAEP256}
			c.Algorithms.UserInfoEncryptionContentEncryption = server.ContentEncryptionAlgorithmSet{0}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := validConfig(t)
			mutate(&cfg)
			deps := validDependencies()
			deps.ClientEncryptionKeys = fakeClientEncryptionKeySource{}
			if _, err := server.New(cfg, deps); err == nil {
				t.Fatalf("New(%s) = nil error, want error", name)
			}
		})
	}
}

// TestNewAcceptsValidUserInfoConfig is the positive counterpart of
// TestNewRejectsInvalidUserInfoConfig.
func TestNewAcceptsValidUserInfoConfig(t *testing.T) {
	cfg := validConfig(t)
	cfg.Algorithms.UserInfo = fapi.ES256
	cfg.Algorithms.UserInfoEncryptionKeyManagement = server.KeyManagementAlgorithmSet{fapi.RSAOAEP256}
	cfg.Algorithms.UserInfoEncryptionContentEncryption = server.ContentEncryptionAlgorithmSet{fapi.A256GCM}
	deps := validDependencies()
	deps.ClientEncryptionKeys = fakeClientEncryptionKeySource{}

	if _, err := server.New(cfg, deps); err != nil {
		t.Fatalf("New(valid userinfo config): %v", err)
	}
}

// TestNewRequiresClientEncryptionKeysWhenUserInfoEncryptionConfigured
// mirrors TestNewRequiresClientEncryptionKeysWhenIDTokenEncryptionConfigured
// for the UserInfo encryption allow-list.
func TestNewRequiresClientEncryptionKeysWhenUserInfoEncryptionConfigured(t *testing.T) {
	cfg := validConfig(t)
	cfg.Algorithms.UserInfoEncryptionKeyManagement = server.KeyManagementAlgorithmSet{fapi.RSAOAEP256}
	cfg.Algorithms.UserInfoEncryptionContentEncryption = server.ContentEncryptionAlgorithmSet{fapi.A256GCM}
	deps := validDependencies()

	if _, err := server.New(cfg, deps); err == nil {
		t.Fatalf("New(userinfo encryption configured, no client encryption keys) = nil error, want error")
	}

	deps.ClientEncryptionKeys = fakeClientEncryptionKeySource{}
	if _, err := server.New(cfg, deps); err != nil {
		t.Fatalf("New(userinfo encryption configured, with client encryption keys): %v", err)
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

// TestNewRejectsLoopbackHTTPURLsUnderProduction covers L-2:
// fapi.AllowLoopbackHTTP exists for local development only, and its
// http:// scheme exception must not silently carry into a
// configuration built for AssuranceProduction.
func TestNewRejectsLoopbackHTTPURLsUnderProduction(t *testing.T) {
	loopbackIssuer, err := fapi.ParseIssuerURL("http://localhost:9999", fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}
	loopbackEndpoint, err := fapi.ParseEndpointURL("http://localhost:9999/token", fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}

	cases := map[string]func(*server.Config){
		"loopback issuer":           func(c *server.Config) { c.Issuer = loopbackIssuer },
		"loopback authorization ep": func(c *server.Config) { c.Endpoints.Authorization = loopbackEndpoint },
		"loopback token ep":         func(c *server.Config) { c.Endpoints.Token = loopbackEndpoint },
		"loopback par ep":           func(c *server.Config) { c.Endpoints.PushedAuthorizationRequest = loopbackEndpoint },
		"loopback jwks ep":          func(c *server.Config) { c.Endpoints.JWKS = loopbackEndpoint },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := validConfig(t)
			cfg.Assurance = server.AssuranceProduction
			mutate(&cfg)
			deps := validDependencies()
			deps.Audit = &fakeAuditSink{}
			if _, err := server.New(cfg, deps); err == nil {
				t.Fatalf("New(production, %s) = nil error, want error", name)
			}
		})
	}

	// The same loopback issuer under AssuranceDevelopment is fine — this
	// option exists precisely for that case.
	cfg := validConfig(t)
	cfg.Issuer = loopbackIssuer
	if _, err := server.New(cfg, validDependencies()); err != nil {
		t.Fatalf("New(development, loopback issuer): %v", err)
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

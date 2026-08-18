package client_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/storage"
)

const (
	testIssuer   = "https://as.example.com"
	testClientID = "test-client"
	testRedirect = "https://rp.example.com/callback"
)

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

// fakeKeyManager backs client's own signing purposes with real ECDSA
// keys, so signatures it produces can be verified with ordinary
// crypto/ecdsa — matching internal/jose's ASN.1 DER expectation for
// crypto.Signer.Sign.
type fakeKeyManager struct {
	mu   sync.Mutex
	keys map[keys.SigningPurpose]*ecdsa.PrivateKey
}

func newFakeKeyManager(t *testing.T, purposes ...keys.SigningPurpose) *fakeKeyManager {
	t.Helper()
	m := &fakeKeyManager{keys: map[keys.SigningPurpose]*ecdsa.PrivateKey{}}
	for _, p := range purposes {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate key for purpose %v: %v", p, err)
		}
		m.keys[p] = priv
	}
	return m
}

func (m *fakeKeyManager) keyID(purpose keys.SigningPurpose) string {
	return fmt.Sprintf("client-kid-%d", purpose)
}

func (m *fakeKeyManager) Sign(ctx context.Context, req keys.SigningRequest) (keys.Signature, error) {
	m.mu.Lock()
	priv, ok := m.keys[req.Purpose]
	m.mu.Unlock()
	if !ok {
		return keys.Signature{}, fmt.Errorf("fakeKeyManager: no key for purpose %v", req.Purpose)
	}
	sig, err := ecdsa.SignASN1(rand.Reader, priv, req.Digest)
	if err != nil {
		return keys.Signature{}, err
	}
	return keys.Signature{KeyID: m.keyID(req.Purpose), Value: sig}, nil
}

func (m *fakeKeyManager) PublicKey(ctx context.Context, purpose keys.SigningPurpose, algorithm fapi.SignatureAlgorithm) (keys.PublicKeyInfo, error) {
	m.mu.Lock()
	priv, ok := m.keys[purpose]
	m.mu.Unlock()
	if !ok {
		return keys.PublicKeyInfo{}, fmt.Errorf("fakeKeyManager: no key for purpose %v", purpose)
	}
	return keys.PublicKeyInfo{KeyID: m.keyID(purpose), PublicKey: &priv.PublicKey}, nil
}

// fakeIssuerKeySource stands in for the authorization server's own
// published verification keys.
type fakeIssuerKeySource struct {
	keys map[keys.IssuerVerificationPurpose]crypto.PublicKey
}

func (f *fakeIssuerKeySource) ResolveIssuerKeys(ctx context.Context, req keys.IssuerKeyRequest) (keys.IssuerKeySet, error) {
	pub, ok := f.keys[req.Purpose]
	if !ok {
		return keys.IssuerKeySet{}, fmt.Errorf("fakeIssuerKeySource: no key for purpose %v", req.Purpose)
	}
	return keys.IssuerKeySet{Keys: []keys.IssuerKey{{KeyID: "as-kid", Algorithm: fapi.ES256, PublicKey: pub}}}, nil
}

// fakeSessionStore is an in-memory storage.SessionStore.
type fakeSessionStore struct {
	mu       sync.Mutex
	sessions map[string]storage.NewSession
}

func newFakeSessionStore() *fakeSessionStore {
	return &fakeSessionStore{sessions: map[string]storage.NewSession{}}
}

func (f *fakeSessionStore) Create(ctx context.Context, s storage.NewSession) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sessions[s.State] = s
	return nil
}

func (f *fakeSessionStore) Consume(ctx context.Context, c storage.SessionConsumption) (storage.ConsumedSession, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.sessions[c.State]
	if !ok {
		return storage.ConsumedSession{}, fmt.Errorf("fakeSessionStore: unknown state")
	}
	delete(f.sessions, c.State)
	return storage.ConsumedSession{
		Nonce: s.Nonce, PKCEVerifier: s.PKCEVerifier, ExpectedIssuer: s.ExpectedIssuer,
		ExpectedRedirectURI: s.ExpectedRedirectURI, ExpectedResponseMode: s.ExpectedResponseMode,
		ExpiresAt: s.ExpiresAt,
	}, nil
}

func validConfig(t *testing.T) client.Config {
	t.Helper()
	issuer, err := fapi.ParseIssuerURL(testIssuer)
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}
	authz, err := fapi.ParseEndpointURL(testIssuer + "/authorize")
	if err != nil {
		t.Fatalf("ParseEndpointURL(authorize): %v", err)
	}
	tok, err := fapi.ParseEndpointURL(testIssuer + "/token")
	if err != nil {
		t.Fatalf("ParseEndpointURL(token): %v", err)
	}
	par, err := fapi.ParseEndpointURL(testIssuer + "/par")
	if err != nil {
		t.Fatalf("ParseEndpointURL(par): %v", err)
	}
	return client.Config{
		Issuer:      issuer,
		ClientID:    testClientID,
		RedirectURI: testRedirect,
		Endpoints:   client.Endpoints{Authorization: authz, Token: tok, PushedAuthorizationRequest: par},
		Profile:     client.ProfileFAPISecurity,
		Algorithms: client.Algorithms{
			ClientAuthentication: fapi.ES256,
			DPoP:                 fapi.ES256,
			IDToken:              fapi.ES256,
		},
		Limits: client.Limits{
			ClientAssertionLifetime: time.Minute,
			SessionLifetime:         5 * time.Minute,
			MaxIDTokenLifetime:      5 * time.Minute,
			MaxClockSkew:            5 * time.Second,
			HTTPTimeout:             5 * time.Second,
			MaxHTTPResponseBytes:    1 << 16,
		},
	}
}

func validDependencies(t *testing.T) client.Dependencies {
	t.Helper()
	return client.Dependencies{
		Sessions: newFakeSessionStore(),
		Keys: newFakeKeyManager(t,
			keys.ClientAuthentication, keys.RequestObjectSigning, keys.DPoPProofSigning),
		IssuerKeys: &fakeIssuerKeySource{keys: map[keys.IssuerVerificationPurpose]crypto.PublicKey{}},
		HTTP:       noopHTTPClient{},
		Clock:      fixedClock{now: time.Now()},
		Random:     rand.Reader,
	}
}

type noopHTTPClient struct{}

func (noopHTTPClient) Do(*http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("noopHTTPClient: not implemented")
}

func TestNewAcceptsValidConfig(t *testing.T) {
	if _, err := client.New(validConfig(t), validDependencies(t)); err != nil {
		t.Fatalf("New: %v", err)
	}
}

func TestNewRejectsInvalidConfig(t *testing.T) {
	cases := map[string]func(*client.Config){
		"zero issuer":             func(c *client.Config) { c.Issuer = fapi.URL{} },
		"empty client id":         func(c *client.Config) { c.ClientID = "" },
		"empty redirect uri":      func(c *client.Config) { c.RedirectURI = "" },
		"zero authorization ep":   func(c *client.Config) { c.Endpoints.Authorization = fapi.URL{} },
		"zero token ep":           func(c *client.Config) { c.Endpoints.Token = fapi.URL{} },
		"zero par ep":             func(c *client.Config) { c.Endpoints.PushedAuthorizationRequest = fapi.URL{} },
		"invalid profile":         func(c *client.Config) { c.Profile = 0 },
		"invalid client auth alg": func(c *client.Config) { c.Algorithms.ClientAuthentication = 0 },
		"invalid dpop alg":        func(c *client.Config) { c.Algorithms.DPoP = 0 },
		"invalid id token alg":    func(c *client.Config) { c.Algorithms.IDToken = 0 },
		"zero assertion lifetime": func(c *client.Config) { c.Limits.ClientAssertionLifetime = 0 },
		"zero session lifetime":   func(c *client.Config) { c.Limits.SessionLifetime = 0 },
		"zero max id token life":  func(c *client.Config) { c.Limits.MaxIDTokenLifetime = 0 },
		"negative clock skew":     func(c *client.Config) { c.Limits.MaxClockSkew = -time.Second },
		"zero http timeout":       func(c *client.Config) { c.Limits.HTTPTimeout = 0 },
		"zero max response bytes": func(c *client.Config) { c.Limits.MaxHTTPResponseBytes = 0 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := validConfig(t)
			mutate(&cfg)
			if _, err := client.New(cfg, validDependencies(t)); err == nil {
				t.Fatalf("New(%s) = nil error, want error", name)
			}
		})
	}
}

func TestNewRequiresMessageSigningConfigUnderThatProfile(t *testing.T) {
	cfg := validConfig(t)
	cfg.Profile = client.ProfileFAPISecurityWithMessageSigning
	deps := validDependencies(t)

	if _, err := client.New(cfg, deps); err == nil {
		t.Fatalf("New(message signing, unconfigured) = nil error, want error")
	}

	cfg.Algorithms.RequestObject = fapi.ES256
	cfg.Algorithms.JARM = fapi.ES256
	cfg.Limits.RequestObjectLifetime = time.Minute
	cfg.Limits.MaxJARMResponseLifetime = time.Minute
	if _, err := client.New(cfg, deps); err != nil {
		t.Fatalf("New(message signing, fully configured): %v", err)
	}
}

func TestNewRejectsMissingDependencies(t *testing.T) {
	cases := map[string]func(*client.Dependencies){
		"nil sessions":    func(d *client.Dependencies) { d.Sessions = nil },
		"nil keys":        func(d *client.Dependencies) { d.Keys = nil },
		"nil issuer keys": func(d *client.Dependencies) { d.IssuerKeys = nil },
		"nil http":        func(d *client.Dependencies) { d.HTTP = nil },
		"nil clock":       func(d *client.Dependencies) { d.Clock = nil },
		"nil random":      func(d *client.Dependencies) { d.Random = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			deps := validDependencies(t)
			mutate(&deps)
			if _, err := client.New(validConfig(t), deps); err == nil {
				t.Fatalf("New(%s) = nil error, want error", name)
			}
		})
	}
}

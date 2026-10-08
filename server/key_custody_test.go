package server_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/keys/ephemeral"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// custodyKeyManager is a fakeKeyManager declaring exactly custody.
type custodyKeyManager struct {
	*fakeKeyManager
	custody keys.KeyCustody
}

func (c custodyKeyManager) KeyCustody() keys.KeyCustody { return c.custody }

// undeclaredKeyManager has fakeKeyManager's methods but, being a
// distinct type, not its test-only KeyCustody.
type undeclaredKeyManager struct{ inner *fakeKeyManager }

func (u undeclaredKeyManager) Sign(ctx context.Context, req keys.SigningRequest) (keys.Signature, error) {
	return u.inner.Sign(ctx, req)
}

func (u undeclaredKeyManager) PublicKey(ctx context.Context, p keys.SigningPurpose, a fapi.SignatureAlgorithm) (keys.PublicKeyInfo, error) {
	return u.inner.PublicKey(ctx, p, a)
}

func declaredSignerKeys(t *testing.T, custody keys.KeyCustody) keys.KeyManager {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	purposes := []keys.SigningPurpose{keys.IDTokenSigning, keys.JARMSigning, keys.AccessTokenSigning}
	specs := make([]keys.SignerSpec, 0, len(purposes))
	for _, p := range purposes {
		specs = append(specs, keys.SignerSpec{Purpose: p, Algorithm: fapi.ES256, Signer: priv})
	}
	km, err := keys.NewKeyManagerFromSigners(specs, keys.DeclareCustody(custody))
	if err != nil {
		t.Fatalf("NewKeyManagerFromSigners: %v", err)
	}
	return km
}

func TestNewProductionRequiresKeyCustody(t *testing.T) {
	durable := keys.KeyCustody{Durable: true}
	ephemeralKeys, err := ephemeral.NewKeyManager(map[keys.SigningPurpose]fapi.SignatureAlgorithm{keys.IDTokenSigning: fapi.ES256, keys.AccessTokenSigning: fapi.ES256})
	if err != nil {
		t.Fatalf("ephemeral.NewKeyManager: %v", err)
	}
	cases := map[string]struct {
		scaled  bool
		mutate  func(t *testing.T, d *server.Dependencies)
		wantErr string // "" = accepted
	}{
		"declared durable signer keys": {false, func(t *testing.T, d *server.Dependencies) {
			km := declaredSignerKeys(t, durable)
			d.Keys = km
			d.AccessTokens = server.JWTAccessTokens{Keys: km, Algorithm: fapi.ES256}
		}, ""},
		"ephemeral keys": {false, func(_ *testing.T, d *server.Dependencies) { d.Keys = ephemeralKeys }, "dependencies: keys must implement keys.KeyCustodyAssurance"},
		"undeclared access token keys": {false, func(_ *testing.T, d *server.Dependencies) {
			d.AccessTokens = server.JWTAccessTokens{Keys: undeclaredKeyManager{newTestKeyManager()}, Algorithm: fapi.ES256}
		}, "access_tokens keys must implement keys.KeyCustodyAssurance"},
		"keys declared not durable": {false, func(_ *testing.T, d *server.Dependencies) {
			d.Keys = custodyKeyManager{newTestKeyManager(), keys.KeyCustody{}}
		}, "keys must declare Durable"},
		"scaled, keys not cross-instance consistent": {true, func(_ *testing.T, d *server.Dependencies) {
			d.Keys = custodyKeyManager{newTestKeyManager(), durable}
		}, "keys must declare CrossInstanceConsistent"},
		"scaled, keys cross-instance consistent": {true, func(t *testing.T, d *server.Dependencies) {
			km := declaredSignerKeys(t, keys.KeyCustody{Durable: true, CrossInstanceConsistent: true})
			d.Keys = km
			d.AccessTokens = server.JWTAccessTokens{Keys: km, Algorithm: fapi.ES256}
		}, ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := validConfig(t)
			cfg.Assurance = server.AssuranceProduction
			cfg.Deployment = map[bool]server.Deployment{false: server.DeploymentSingleInstance, true: server.DeploymentHorizontallyScaled}[tc.scaled]
			deps := validDependencies()
			deps.Audit = &fakeAuditSink{}
			deps.Replay = capReplayStore{caps: storage.Capabilities{Durable: true, AtomicConsume: true, CrossInstanceConsistent: true}}
			tc.mutate(t, &deps)
			_, err := server.New(cfg, deps)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("New: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("New() error = %v, want one containing %q", err, tc.wantErr)
			}
		})
	}
}

// TestNewDevelopmentAcceptsEphemeralKeys pins that the requirement is
// production-only: keys/ephemeral remains the development default.
func TestNewDevelopmentAcceptsEphemeralKeys(t *testing.T) {
	km, err := ephemeral.NewKeyManager(map[keys.SigningPurpose]fapi.SignatureAlgorithm{keys.IDTokenSigning: fapi.ES256, keys.AccessTokenSigning: fapi.ES256})
	if err != nil {
		t.Fatalf("ephemeral.NewKeyManager: %v", err)
	}
	cfg := validConfig(t)
	deps := validDependencies()
	deps.Keys = km
	deps.AccessTokens = server.JWTAccessTokens{Keys: km, Algorithm: fapi.ES256}
	if _, err := server.New(cfg, deps); err != nil {
		t.Fatalf("New(development, ephemeral keys): %v", err)
	}
}

package server_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	intfed "github.com/idfoundry/fapigo/internal/federation"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/server"
)

func federationConfiguredConfig(t *testing.T) server.Config {
	t.Helper()
	cfg := validConfig(t)
	cfg.Federation = server.FederationConfig{
		EntityID: "https://as.example.org", Lifetime: time.Hour, Algorithm: fapi.ES256,
	}
	return cfg
}

func TestNewAcceptsZeroValueFederationConfig(t *testing.T) {
	cfg := validConfig(t)
	if cfg.Federation.EntityID != "" {
		t.Fatalf("validConfig's zero-value Federation.EntityID = %q, want empty", cfg.Federation.EntityID)
	}
	srv, err := server.New(cfg, validDependencies())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := srv.EntityConfiguration(context.Background(), nil); err == nil {
		t.Fatalf("EntityConfiguration(federation not configured) = nil error, want error")
	}
}

func TestNewRejectsInvalidFederationConfig(t *testing.T) {
	validCfg := federationConfiguredConfig(t)

	cases := map[string]func(*server.Config){
		"non-https entity ID": func(c *server.Config) { c.Federation.EntityID = "http://as.example.org" },
		"zero lifetime":       func(c *server.Config) { c.Federation.Lifetime = 0 },
		"zero algorithm":      func(c *server.Config) { c.Federation.Algorithm = 0 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := validCfg
			mutate(&cfg)
			if _, err := server.New(cfg, validDependencies()); err == nil {
				t.Fatalf("New(%s) = nil error, want error", name)
			}
		})
	}
}

func TestServerEntityConfiguration(t *testing.T) {
	cfg := federationConfiguredConfig(t)
	cfg.Federation.AuthorityHints = []string{"https://ta.example.org"}
	deps := validDependencies()
	deps.Keys = &fakeKeyManager{key: generateKey(t), keyID: "as-fed-kid"}

	srv, err := server.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	metadata := map[string]json.RawMessage{
		"openid_provider": json.RawMessage(`{"issuer":"https://as.example.org"}`),
	}
	token, err := srv.EntityConfiguration(context.Background(), metadata)
	if err != nil {
		t.Fatalf("EntityConfiguration: %v", err)
	}

	stmt, err := intfed.Parse(token)
	if err != nil {
		t.Fatalf("intfed.Parse: %v", err)
	}
	if stmt.ClaimedIssuer() != "https://as.example.org" || stmt.ClaimedSubject() != "https://as.example.org" {
		t.Errorf("iss/sub = %q/%q, want both equal to the configured entity ID", stmt.ClaimedIssuer(), stmt.ClaimedSubject())
	}
	if got := stmt.ClaimedAuthorityHints(); len(got) != 1 || got[0] != "https://ta.example.org" {
		t.Errorf("ClaimedAuthorityHints = %v, want [https://ta.example.org]", got)
	}

	candidates, err := jose.ParseJWKSet(stmt.ClaimedJWKS())
	if err != nil {
		t.Fatalf("jose.ParseJWKSet(ClaimedJWKS): %v", err)
	}
	if len(candidates) != 1 {
		t.Fatalf("ParseJWKSet returned %d keys, want 1", len(candidates))
	}
	claims, err := stmt.Verify(candidates[0].PublicKey, intfed.VerifyPolicy{
		ExpectedIssuer: "https://as.example.org", ExpectedSubject: "https://as.example.org",
		Algorithm: fapi.ES256, Now: time.Now(), MaxLifetime: 2 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Verify(self-issued statement against its own claimed key): %v", err)
	}
	op, ok := claims.Metadata["openid_provider"]
	if !ok {
		t.Fatalf("Metadata missing openid_provider: %v", claims.Metadata)
	}
	var opMeta struct {
		Issuer string `json:"issuer"`
	}
	if err := json.Unmarshal(op, &opMeta); err != nil || opMeta.Issuer != "https://as.example.org" {
		t.Errorf("openid_provider = %s, want issuer to pass through", op)
	}
}

func TestServerEntityConfigurationRejectsMissingSigningKey(t *testing.T) {
	cfg := federationConfiguredConfig(t)
	deps := validDependencies()
	deps.Keys = brokenKeyManager{}

	srv, err := server.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := srv.EntityConfiguration(context.Background(), nil); err == nil {
		t.Fatalf("EntityConfiguration(key manager fails) = nil error, want error")
	}
}

// brokenKeyManager always fails to resolve a public key, for exercising
// EntityConfiguration's own signing-key-resolution error path.
type brokenKeyManager struct{}

func (brokenKeyManager) Sign(context.Context, keys.SigningRequest) (keys.Signature, error) {
	return keys.Signature{}, fmt.Errorf("brokenKeyManager: sign always fails")
}

func (brokenKeyManager) PublicKey(context.Context, keys.SigningPurpose, fapi.SignatureAlgorithm) (keys.PublicKeyInfo, error) {
	return keys.PublicKeyInfo{}, fmt.Errorf("brokenKeyManager: no key available")
}

// emptyKidKeyManager wraps a real key manager but reports an empty
// "kid" for every purpose — reachable in practice through a
// misconfigured KeyManager backend, so keys.PublicJWKS's own explicit
// empty-kid guard can be exercised directly.
type emptyKidKeyManager struct{ *fakeKeyManager }

func (m emptyKidKeyManager) PublicKey(ctx context.Context, purpose keys.SigningPurpose, algorithm fapi.SignatureAlgorithm) (keys.PublicKeyInfo, error) {
	info, err := m.fakeKeyManager.PublicKey(ctx, purpose, algorithm)
	if err != nil {
		return keys.PublicKeyInfo{}, err
	}
	info.KeyID = ""
	return info, nil
}

func TestServerEntityConfigurationRejectsEmptyKeyID(t *testing.T) {
	cfg := federationConfiguredConfig(t)
	deps := validDependencies()
	deps.Keys = emptyKidKeyManager{&fakeKeyManager{key: generateKey(t), keyID: "as-fed-kid"}}

	srv, err := server.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := srv.EntityConfiguration(context.Background(), nil); err == nil {
		t.Fatalf("EntityConfiguration(key manager returns empty kid) = nil error, want error")
	}
}

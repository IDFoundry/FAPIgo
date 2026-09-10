package client_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	intfed "github.com/idfoundry/fapigo/internal/federation"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/keys"
)

func federationConfiguredConfig(t *testing.T) client.Config {
	t.Helper()
	cfg := validConfig(t)
	cfg.Federation = client.FederationConfig{
		EntityID:  "https://rp.example.org",
		Lifetime:  time.Hour,
		Algorithm: fapi.ES256,
	}
	return cfg
}

func federationConfiguredDependencies(t *testing.T) client.Dependencies {
	t.Helper()
	deps := validDependencies(t)
	deps.Keys = newFakeKeyManager(t,
		keys.ClientAuthentication, keys.RequestObjectSigning, keys.DPoPProofSigning, keys.FederationEntitySigning)
	return deps
}

func TestNewAcceptsZeroValueFederationConfig(t *testing.T) {
	cfg := validConfig(t)
	if cfg.Federation.EntityID != "" {
		t.Fatalf("validConfig's zero-value Federation.EntityID = %q, want empty", cfg.Federation.EntityID)
	}
	c, err := client.New(cfg, validDependencies(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.EntityConfiguration(context.Background(), nil); err == nil {
		t.Fatalf("EntityConfiguration(federation not configured) = nil error, want error")
	}
}

func TestNewRejectsInvalidFederationConfig(t *testing.T) {
	validCfg := federationConfiguredConfig(t)

	cases := map[string]func(*client.Config){
		"non-https entity ID": func(c *client.Config) { c.Federation.EntityID = "http://rp.example.org" },
		"zero lifetime":       func(c *client.Config) { c.Federation.Lifetime = 0 },
		"zero algorithm":      func(c *client.Config) { c.Federation.Algorithm = 0 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := validCfg
			mutate(&cfg)
			if _, err := client.New(cfg, federationConfiguredDependencies(t)); err == nil {
				t.Fatalf("New(%s) = nil error, want error", name)
			}
		})
	}
}

func TestClientEntityConfigurationRejectsMissingSigningKey(t *testing.T) {
	cfg := federationConfiguredConfig(t)
	deps := validDependencies(t)
	// Deliberately omit keys.FederationEntitySigning: this client's own
	// Keys never registered a federation signing key, mirroring a
	// deployment that enables Config.Federation without actually
	// provisioning one.
	deps.Keys = newFakeKeyManager(t, keys.ClientAuthentication, keys.RequestObjectSigning, keys.DPoPProofSigning)
	c, err := client.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.EntityConfiguration(context.Background(), nil); err == nil {
		t.Fatalf("EntityConfiguration(no federation signing key registered) = nil error, want error")
	}
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

func TestClientEntityConfigurationRejectsEmptyKeyID(t *testing.T) {
	cfg := federationConfiguredConfig(t)
	deps := validDependencies(t)
	deps.Keys = emptyKidKeyManager{newFakeKeyManager(t, keys.FederationEntitySigning)}
	c, err := client.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.EntityConfiguration(context.Background(), nil); err == nil {
		t.Fatalf("EntityConfiguration(key manager returns empty kid) = nil error, want error")
	}
}

func TestClientEntityConfiguration(t *testing.T) {
	cfg := federationConfiguredConfig(t)
	cfg.Federation.AuthorityHints = []string{"https://ta.example.org"}
	c, err := client.New(cfg, federationConfiguredDependencies(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	metadata := map[string]json.RawMessage{
		"openid_relying_party": json.RawMessage(`{"redirect_uris":["https://rp.example.org/cb"]}`),
	}
	token, err := c.EntityConfiguration(context.Background(), metadata)
	if err != nil {
		t.Fatalf("EntityConfiguration: %v", err)
	}

	stmt, err := intfed.Parse(token)
	if err != nil {
		t.Fatalf("intfed.Parse: %v", err)
	}
	if stmt.ClaimedIssuer() != "https://rp.example.org" || stmt.ClaimedSubject() != "https://rp.example.org" {
		t.Errorf("iss/sub = %q/%q, want both equal to the configured entity ID", stmt.ClaimedIssuer(), stmt.ClaimedSubject())
	}
	if got := stmt.ClaimedAuthorityHints(); len(got) != 1 || got[0] != "https://ta.example.org" {
		t.Errorf("ClaimedAuthorityHints = %v, want [https://ta.example.org]", got)
	}

	// Full round trip: verify the statement's signature against its own
	// claimed jwks, exactly as federation.Resolver.verifySelfSigned
	// does for any self-signed Entity Configuration it encounters.
	candidates, err := jose.ParseJWKSet(stmt.ClaimedJWKS())
	if err != nil {
		t.Fatalf("jose.ParseJWKSet(ClaimedJWKS): %v", err)
	}
	if len(candidates) != 1 {
		t.Fatalf("ParseJWKSet returned %d keys, want 1", len(candidates))
	}
	claims, err := stmt.Verify(candidates[0].PublicKey, intfed.VerifyPolicy{
		ExpectedIssuer: "https://rp.example.org", ExpectedSubject: "https://rp.example.org",
		Algorithm: fapi.ES256, Now: time.Now(), MaxLifetime: 2 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Verify(self-issued statement against its own claimed key): %v", err)
	}
	rp, ok := claims.Metadata["openid_relying_party"]
	if !ok {
		t.Fatalf("Metadata missing openid_relying_party: %v", claims.Metadata)
	}
	var rpMeta struct {
		RedirectURIs []string `json:"redirect_uris"`
	}
	if err := json.Unmarshal(rp, &rpMeta); err != nil || len(rpMeta.RedirectURIs) != 1 {
		t.Errorf("openid_relying_party = %s, want the redirect_uris passed through", rp)
	}
}

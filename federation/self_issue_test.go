package federation_test

import (
	"encoding/json"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/federation"
	intfed "github.com/idfoundry/fapigo/internal/federation"
)

func validSelfIssueConfig() federation.SelfIssueConfig {
	return federation.SelfIssueConfig{
		EntityID: "https://rp.example.org", Lifetime: time.Hour,
	}
}

func validSelfIssueDeps(t *testing.T) federation.SelfIssueDependencies {
	t.Helper()
	key := generateKey(t)
	return federation.SelfIssueDependencies{
		Signer: key, Algorithm: fapi.ES256, KeyID: "rp-fed",
		JWKS: jwksFor(t, "rp-fed", key), Clock: federation.SystemClock{},
	}
}

func TestNewSelfIssuerRejectsInvalidConfig(t *testing.T) {
	validCfg := validSelfIssueConfig()

	cases := map[string]func(*federation.SelfIssueConfig, *federation.SelfIssueDependencies){
		"empty entity ID": func(c *federation.SelfIssueConfig, d *federation.SelfIssueDependencies) { c.EntityID = "" },
		"non-https entity ID": func(c *federation.SelfIssueConfig, d *federation.SelfIssueDependencies) {
			c.EntityID = "http://rp.example.org"
		},
		"zero lifetime": func(c *federation.SelfIssueConfig, d *federation.SelfIssueDependencies) { c.Lifetime = 0 },
		"nil signer":    func(c *federation.SelfIssueConfig, d *federation.SelfIssueDependencies) { d.Signer = nil },
		"empty jwks":    func(c *federation.SelfIssueConfig, d *federation.SelfIssueDependencies) { d.JWKS = nil },
		"nil clock":     func(c *federation.SelfIssueConfig, d *federation.SelfIssueDependencies) { d.Clock = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := validCfg
			deps := validSelfIssueDeps(t)
			mutate(&cfg, &deps)
			if _, err := federation.NewSelfIssuer(cfg, deps); err == nil {
				t.Fatalf("NewSelfIssuer(%s) = nil error, want error", name)
			}
		})
	}
}

func TestSelfIssuerEntityConfigurationRoundTrips(t *testing.T) {
	key := generateKey(t)
	jwks := jwksFor(t, "rp-fed", key)
	now := time.Now()

	s, err := federation.NewSelfIssuer(federation.SelfIssueConfig{
		EntityID:       "https://rp.example.org",
		AuthorityHints: []string{"https://ta.example.org"},
		Lifetime:       time.Hour,
	}, federation.SelfIssueDependencies{
		Signer: key, Algorithm: fapi.ES256, KeyID: "rp-fed", JWKS: jwks,
		Clock: fixedClock{now: now},
	})
	if err != nil {
		t.Fatalf("NewSelfIssuer: %v", err)
	}

	metadata := map[string]json.RawMessage{
		"federation_entity":    federationEntityMetadata(t, "https://rp.example.org/fetch")["federation_entity"],
		"openid_relying_party": json.RawMessage(`{"redirect_uris":["https://rp.example.org/cb"]}`),
	}
	token, err := s.EntityConfiguration(metadata)
	if err != nil {
		t.Fatalf("EntityConfiguration: %v", err)
	}

	stmt, err := intfed.Parse(token)
	if err != nil {
		t.Fatalf("intfed.Parse: %v", err)
	}
	if stmt.ClaimedIssuer() != "https://rp.example.org" || stmt.ClaimedSubject() != "https://rp.example.org" {
		t.Errorf("iss/sub = %q/%q, want both equal to the entity ID", stmt.ClaimedIssuer(), stmt.ClaimedSubject())
	}
	if got := stmt.ClaimedAuthorityHints(); len(got) != 1 || got[0] != "https://ta.example.org" {
		t.Errorf("ClaimedAuthorityHints = %v, want [https://ta.example.org]", got)
	}

	claims, err := stmt.Verify(&key.PublicKey, intfed.VerifyPolicy{
		ExpectedIssuer: "https://rp.example.org", ExpectedSubject: "https://rp.example.org",
		Algorithm: fapi.ES256, Now: now, MaxLifetime: 2 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
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

func TestSelfIssuerEntityConfigurationIsAcceptedBySelfVerification(t *testing.T) {
	// A SelfIssuer's own output must satisfy the exact self-consistency
	// check Resolver.verifySelfSigned performs on every Entity
	// Configuration it encounters — the round trip a peer resolving this
	// entity actually relies on, not merely that intfed.Parse succeeds.
	key := generateKey(t)
	jwks := jwksFor(t, "le", key)
	now := time.Now()

	s, err := federation.NewSelfIssuer(federation.SelfIssueConfig{
		EntityID: "https://le.example.org", Lifetime: time.Hour,
	}, federation.SelfIssueDependencies{
		Signer: key, Algorithm: fapi.ES256, KeyID: "le", JWKS: jwks, Clock: fixedClock{now: now},
	})
	if err != nil {
		t.Fatalf("NewSelfIssuer: %v", err)
	}
	token, err := s.EntityConfiguration(nil)
	if err != nil {
		t.Fatalf("EntityConfiguration: %v", err)
	}

	stmt, err := intfed.Parse(token)
	if err != nil {
		t.Fatalf("intfed.Parse: %v", err)
	}
	if stmt.KeyID() != "le" {
		t.Errorf("KeyID = %q, want \"le\"", stmt.KeyID())
	}
	if _, err := stmt.Verify(&key.PublicKey, intfed.VerifyPolicy{
		ExpectedIssuer: "https://le.example.org", ExpectedSubject: "https://le.example.org",
		Algorithm: fapi.ES256, Now: now, MaxLifetime: 2 * time.Hour,
	}); err != nil {
		t.Fatalf("Verify(self-issued statement against its own claimed key): %v", err)
	}
}

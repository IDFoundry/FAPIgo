package federation_test

import (
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/federation"
	intfed "github.com/idfoundry/fapigo/internal/federation"
)

func validTrustMarkIssueConfig() federation.TrustMarkIssueConfig {
	return federation.TrustMarkIssueConfig{EntityID: "https://issuer.example.org"}
}

func validTrustMarkIssueDeps(t *testing.T) federation.TrustMarkIssueDependencies {
	t.Helper()
	return federation.TrustMarkIssueDependencies{
		Signer: generateKey(t), Algorithm: fapi.ES256, KeyID: "issuer-kid", Clock: federation.SystemClock{},
	}
}

func TestNewTrustMarkIssuerRejectsInvalidConfig(t *testing.T) {
	validCfg := validTrustMarkIssueConfig()

	cases := map[string]func(*federation.TrustMarkIssueConfig, *federation.TrustMarkIssueDependencies){
		"empty entity ID": func(c *federation.TrustMarkIssueConfig, d *federation.TrustMarkIssueDependencies) {
			c.EntityID = ""
		},
		"non-https entity ID": func(c *federation.TrustMarkIssueConfig, d *federation.TrustMarkIssueDependencies) {
			c.EntityID = "http://issuer.example.org"
		},
		"nil signer": func(c *federation.TrustMarkIssueConfig, d *federation.TrustMarkIssueDependencies) {
			d.Signer = nil
		},
		"empty key id": func(c *federation.TrustMarkIssueConfig, d *federation.TrustMarkIssueDependencies) {
			d.KeyID = ""
		},
		"nil clock": func(c *federation.TrustMarkIssueConfig, d *federation.TrustMarkIssueDependencies) {
			d.Clock = nil
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := validCfg
			deps := validTrustMarkIssueDeps(t)
			mutate(&cfg, &deps)
			if _, err := federation.NewTrustMarkIssuer(cfg, deps); err == nil {
				t.Fatalf("NewTrustMarkIssuer(%s) = nil error, want error", name)
			}
		})
	}
}

func TestTrustMarkRoundTrips(t *testing.T) {
	key := generateKey(t)
	now := time.Now()

	i, err := federation.NewTrustMarkIssuer(validTrustMarkIssueConfig(), federation.TrustMarkIssueDependencies{
		Signer: key, Algorithm: fapi.ES256, KeyID: "issuer-kid", Clock: fixedClock{now: now},
	})
	if err != nil {
		t.Fatalf("NewTrustMarkIssuer: %v", err)
	}

	token, err := i.TrustMark(federation.TrustMarkParams{
		Subject: "https://rp.example.org", TrustMarkType: "https://federation.example.org/marks/certified",
		Lifetime: time.Hour,
	})
	if err != nil {
		t.Fatalf("TrustMark: %v", err)
	}

	tm, err := intfed.ParseTrustMark(token)
	if err != nil {
		t.Fatalf("intfed.ParseTrustMark: %v", err)
	}
	if tm.ClaimedIssuer() != "https://issuer.example.org" || tm.ClaimedSubject() != "https://rp.example.org" {
		t.Errorf("iss/sub = %q/%q, want issuer/rp", tm.ClaimedIssuer(), tm.ClaimedSubject())
	}
	if tm.KeyID() != "issuer-kid" {
		t.Errorf("KeyID = %q, want \"issuer-kid\"", tm.KeyID())
	}
	claims, err := tm.Verify(&key.PublicKey, intfed.TrustMarkVerifyPolicy{
		ExpectedSubject: "https://rp.example.org", ExpectedTrustMarkType: "https://federation.example.org/marks/certified",
		Algorithm: fapi.ES256, Now: now,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.ExpiresAt.Unix() != now.Add(time.Hour).Unix() {
		t.Errorf("ExpiresAt = %v, want %v", claims.ExpiresAt, now.Add(time.Hour))
	}
}

func TestTrustMarkRejectsInvalidParams(t *testing.T) {
	i, err := federation.NewTrustMarkIssuer(validTrustMarkIssueConfig(), validTrustMarkIssueDeps(t))
	if err != nil {
		t.Fatalf("NewTrustMarkIssuer: %v", err)
	}
	cases := map[string]federation.TrustMarkParams{
		"empty subject":   {TrustMarkType: "https://federation.example.org/marks/certified"},
		"invalid subject": {Subject: "not-a-url", TrustMarkType: "https://federation.example.org/marks/certified"},
		"empty type":      {Subject: "https://rp.example.org"},
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := i.TrustMark(p); err == nil {
				t.Fatalf("TrustMark(%s) = nil error, want error", name)
			}
		})
	}
}

func TestTrustMarkIncludesDelegation(t *testing.T) {
	i, err := federation.NewTrustMarkIssuer(validTrustMarkIssueConfig(), validTrustMarkIssueDeps(t))
	if err != nil {
		t.Fatalf("NewTrustMarkIssuer: %v", err)
	}
	token, err := i.TrustMark(federation.TrustMarkParams{
		Subject: "https://rp.example.org", TrustMarkType: "https://federation.example.org/marks/certified",
		Delegation: "a.b.c",
	})
	if err != nil {
		t.Fatalf("TrustMark: %v", err)
	}
	tm, err := intfed.ParseTrustMark(token)
	if err != nil {
		t.Fatalf("intfed.ParseTrustMark: %v", err)
	}
	if tm.ClaimedDelegation() != "a.b.c" {
		t.Errorf("ClaimedDelegation = %q, want \"a.b.c\"", tm.ClaimedDelegation())
	}
}

func TestDelegationRoundTrips(t *testing.T) {
	key := generateKey(t)
	now := time.Now()

	i, err := federation.NewTrustMarkIssuer(federation.TrustMarkIssueConfig{
		EntityID: "https://owner.example.org",
	}, federation.TrustMarkIssueDependencies{
		Signer: key, Algorithm: fapi.ES256, KeyID: "owner-kid", Clock: fixedClock{now: now},
	})
	if err != nil {
		t.Fatalf("NewTrustMarkIssuer: %v", err)
	}

	token, err := i.Delegation(federation.DelegationParams{
		Subject: "https://issuer.example.org", TrustMarkType: "https://federation.example.org/marks/certified",
		Lifetime: time.Hour,
	})
	if err != nil {
		t.Fatalf("Delegation: %v", err)
	}

	d, err := intfed.ParseTrustMarkDelegation(token)
	if err != nil {
		t.Fatalf("intfed.ParseTrustMarkDelegation: %v", err)
	}
	if d.ClaimedIssuer() != "https://owner.example.org" || d.ClaimedSubject() != "https://issuer.example.org" {
		t.Errorf("iss/sub = %q/%q, want owner/issuer", d.ClaimedIssuer(), d.ClaimedSubject())
	}
	if d.KeyID() != "owner-kid" {
		t.Errorf("KeyID = %q, want \"owner-kid\"", d.KeyID())
	}
	claims, err := d.Verify(&key.PublicKey, intfed.TrustMarkDelegationVerifyPolicy{
		ExpectedIssuer: "https://owner.example.org", ExpectedSubject: "https://issuer.example.org",
		ExpectedTrustMarkType: "https://federation.example.org/marks/certified",
		Algorithm:             fapi.ES256, Now: now,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.ExpiresAt.Unix() != now.Add(time.Hour).Unix() {
		t.Errorf("ExpiresAt = %v, want %v", claims.ExpiresAt, now.Add(time.Hour))
	}
}

func TestDelegationRejectsInvalidParams(t *testing.T) {
	i, err := federation.NewTrustMarkIssuer(validTrustMarkIssueConfig(), validTrustMarkIssueDeps(t))
	if err != nil {
		t.Fatalf("NewTrustMarkIssuer: %v", err)
	}
	cases := map[string]federation.DelegationParams{
		"empty subject":     {TrustMarkType: "https://federation.example.org/marks/certified"},
		"invalid subject":   {Subject: "not-a-url", TrustMarkType: "https://federation.example.org/marks/certified"},
		"subject == issuer": {Subject: "https://issuer.example.org", TrustMarkType: "https://federation.example.org/marks/certified"},
		"empty type":        {Subject: "https://delegate.example.org"},
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := i.Delegation(p); err == nil {
				t.Fatalf("Delegation(%s) = nil error, want error", name)
			}
		})
	}
}

func TestTrustMarkAndDelegationWrapCreateFailure(t *testing.T) {
	// Every input TrustMark/Delegation themselves check is validated
	// before intfed.Create{TrustMark,TrustMarkDelegation} is ever
	// called — the only way to reach either's own failure path is a bad
	// Algorithm (see the identical reasoning in
	// TestSubordinateStatementWrapsCreateFailure).
	i, err := federation.NewTrustMarkIssuer(validTrustMarkIssueConfig(), federation.TrustMarkIssueDependencies{
		Signer: generateKey(t), Algorithm: fapi.SignatureAlgorithm(255), KeyID: "k", Clock: federation.SystemClock{},
	})
	if err != nil {
		t.Fatalf("NewTrustMarkIssuer: %v", err)
	}
	if _, err := i.TrustMark(federation.TrustMarkParams{
		Subject: "https://rp.example.org", TrustMarkType: "https://federation.example.org/marks/certified",
	}); err == nil {
		t.Fatal("TrustMark(invalid algorithm) = nil error, want error")
	}
	if _, err := i.Delegation(federation.DelegationParams{
		Subject: "https://delegate.example.org", TrustMarkType: "https://federation.example.org/marks/certified",
	}); err == nil {
		t.Fatal("Delegation(invalid algorithm) = nil error, want error")
	}
}

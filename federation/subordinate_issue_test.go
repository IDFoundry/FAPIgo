package federation_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/federation"
	intfed "github.com/idfoundry/fapigo/internal/federation"
)

func validSubordinateIssueConfig() federation.SubordinateIssueConfig {
	return federation.SubordinateIssueConfig{
		EntityID: "https://ta.example.org", Lifetime: time.Hour,
	}
}

func validSubordinateIssueDeps(t *testing.T) federation.SubordinateIssueDependencies {
	t.Helper()
	key := generateKey(t)
	return federation.SubordinateIssueDependencies{
		Signer: key, Algorithm: fapi.ES256, KeyID: "ta-key", Clock: federation.SystemClock{},
	}
}

func TestNewSubordinateIssuerRejectsInvalidConfig(t *testing.T) {
	validCfg := validSubordinateIssueConfig()

	cases := map[string]func(*federation.SubordinateIssueConfig, *federation.SubordinateIssueDependencies){
		"empty entity ID": func(c *federation.SubordinateIssueConfig, d *federation.SubordinateIssueDependencies) {
			c.EntityID = ""
		},
		"non-https entity ID": func(c *federation.SubordinateIssueConfig, d *federation.SubordinateIssueDependencies) {
			c.EntityID = "http://ta.example.org"
		},
		"zero lifetime": func(c *federation.SubordinateIssueConfig, d *federation.SubordinateIssueDependencies) {
			c.Lifetime = 0
		},
		"nil signer": func(c *federation.SubordinateIssueConfig, d *federation.SubordinateIssueDependencies) {
			d.Signer = nil
		},
		"nil clock": func(c *federation.SubordinateIssueConfig, d *federation.SubordinateIssueDependencies) {
			d.Clock = nil
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := validCfg
			deps := validSubordinateIssueDeps(t)
			mutate(&cfg, &deps)
			if _, err := federation.NewSubordinateIssuer(cfg, deps); err == nil {
				t.Fatalf("NewSubordinateIssuer(%s) = nil error, want error", name)
			}
		})
	}
}

func TestSubordinateStatementRoundTrips(t *testing.T) {
	taKey := generateKey(t)
	subKey := generateKey(t)
	subJWKS := jwksFor(t, "sub-key", subKey)
	now := time.Now()

	s, err := federation.NewSubordinateIssuer(federation.SubordinateIssueConfig{
		EntityID: "https://ta.example.org", Lifetime: time.Hour,
	}, federation.SubordinateIssueDependencies{
		Signer: taKey, Algorithm: fapi.ES256, KeyID: "ta-key", Clock: fixedClock{now: now},
	})
	if err != nil {
		t.Fatalf("NewSubordinateIssuer: %v", err)
	}

	token, err := s.SubordinateStatement(federation.SubordinateStatementParams{
		Subject: "https://le.example.org", JWKS: subJWKS,
		SourceEndpoint: "https://ta.example.org/fetch",
	})
	if err != nil {
		t.Fatalf("SubordinateStatement: %v", err)
	}

	stmt, err := intfed.Parse(token)
	if err != nil {
		t.Fatalf("intfed.Parse: %v", err)
	}
	if stmt.ClaimedIssuer() != "https://ta.example.org" || stmt.ClaimedSubject() != "https://le.example.org" {
		t.Errorf("iss/sub = %q/%q, want ta/le", stmt.ClaimedIssuer(), stmt.ClaimedSubject())
	}
	if stmt.KeyID() != "ta-key" {
		t.Errorf("KeyID = %q, want \"ta-key\"", stmt.KeyID())
	}

	claims, err := stmt.Verify(&taKey.PublicKey, intfed.VerifyPolicy{
		ExpectedIssuer: "https://ta.example.org", ExpectedSubject: "https://le.example.org",
		Algorithm: fapi.ES256, Now: now, MaxLifetime: 2 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	var gotJWKS map[string]any
	if err := json.Unmarshal(claims.JWKS, &gotJWKS); err != nil {
		t.Fatalf("unmarshal claims.JWKS: %v", err)
	}
	var wantJWKS map[string]any
	if err := json.Unmarshal(subJWKS, &wantJWKS); err != nil {
		t.Fatalf("unmarshal subJWKS: %v", err)
	}
	if claims.SourceEndpoint != "https://ta.example.org/fetch" {
		t.Errorf("SourceEndpoint = %q, want the fetch endpoint passed through", claims.SourceEndpoint)
	}
}

func TestSubordinateStatementPassesThroughMetadataPolicyAndConstraints(t *testing.T) {
	taKey := generateKey(t)
	subKey := generateKey(t)
	now := time.Now()

	s, err := federation.NewSubordinateIssuer(federation.SubordinateIssueConfig{
		EntityID: "https://ta.example.org", Lifetime: time.Hour,
	}, federation.SubordinateIssueDependencies{
		Signer: taKey, Algorithm: fapi.ES256, KeyID: "ta-key", Clock: fixedClock{now: now},
	})
	if err != nil {
		t.Fatalf("NewSubordinateIssuer: %v", err)
	}

	token, err := s.SubordinateStatement(federation.SubordinateStatementParams{
		Subject: "https://le.example.org", JWKS: jwksFor(t, "sub-key", subKey),
		Constraints: &intfed.Constraints{MaxPathLength: 0, HasMaxPathLength: true},
	})
	if err != nil {
		t.Fatalf("SubordinateStatement: %v", err)
	}

	stmt, err := intfed.Parse(token)
	if err != nil {
		t.Fatalf("intfed.Parse: %v", err)
	}
	constraints := stmt.ClaimedConstraints()
	if constraints == nil || !constraints.HasMaxPathLength || constraints.MaxPathLength != 0 {
		t.Errorf("ClaimedConstraints = %+v, want MaxPathLength 0", constraints)
	}
}

func TestSubordinateStatementRejectsSubjectEqualToIssuer(t *testing.T) {
	s, err := federation.NewSubordinateIssuer(validSubordinateIssueConfig(), validSubordinateIssueDeps(t))
	if err != nil {
		t.Fatalf("NewSubordinateIssuer: %v", err)
	}
	_, err = s.SubordinateStatement(federation.SubordinateStatementParams{
		Subject: "https://ta.example.org", JWKS: jwksFor(t, "k", generateKey(t)),
	})
	if err == nil {
		t.Fatal("SubordinateStatement(subject == issuer) = nil error, want error")
	}
	var fedErr *federation.Error
	if !errors.As(err, &fedErr) {
		t.Fatalf("error = %v, want a *federation.Error", err)
	}
	if fedErr.Code() != federation.ErrorInvalidRequest || fedErr.HTTPStatus() != http.StatusBadRequest {
		t.Errorf("Code/HTTPStatus = %s/%d, want invalid_request/400", fedErr.Code(), fedErr.HTTPStatus())
	}
}

func TestSubordinateStatementRejectsEmptySubject(t *testing.T) {
	s, err := federation.NewSubordinateIssuer(validSubordinateIssueConfig(), validSubordinateIssueDeps(t))
	if err != nil {
		t.Fatalf("NewSubordinateIssuer: %v", err)
	}
	_, err = s.SubordinateStatement(federation.SubordinateStatementParams{JWKS: jwksFor(t, "k", generateKey(t))})
	var fedErr *federation.Error
	if !errors.As(err, &fedErr) || fedErr.Code() != federation.ErrorInvalidRequest {
		t.Errorf("error = %v, want a *federation.Error with code invalid_request", err)
	}
}

func TestSubordinateStatementRejectsInvalidSubject(t *testing.T) {
	s, err := federation.NewSubordinateIssuer(validSubordinateIssueConfig(), validSubordinateIssueDeps(t))
	if err != nil {
		t.Fatalf("NewSubordinateIssuer: %v", err)
	}
	_, err = s.SubordinateStatement(federation.SubordinateStatementParams{
		Subject: "not-a-url", JWKS: jwksFor(t, "k", generateKey(t)),
	})
	var fedErr *federation.Error
	if !errors.As(err, &fedErr) || fedErr.Code() != federation.ErrorInvalidRequest {
		t.Errorf("error = %v, want a *federation.Error with code invalid_request", err)
	}
}

func TestSubordinateStatementWrapsCreateFailure(t *testing.T) {
	// Every input SubordinateStatement itself checks (subject
	// empty/invalid/equal-to-issuer, jwks empty) is validated before
	// intfed.Create is ever called — the only way to reach Create's own
	// failure path is a bad Algorithm, which SubordinateStatement
	// doesn't pre-validate (SelfIssueConfig's own NewSelfIssuer doesn't
	// either; Create is the single source of truth for algorithm
	// validity across every issuer in this package).
	s, err := federation.NewSubordinateIssuer(validSubordinateIssueConfig(), federation.SubordinateIssueDependencies{
		Signer: generateKey(t), Algorithm: fapi.SignatureAlgorithm(255), KeyID: "ta-key", Clock: federation.SystemClock{},
	})
	if err != nil {
		t.Fatalf("NewSubordinateIssuer: %v", err)
	}
	if _, err := s.SubordinateStatement(federation.SubordinateStatementParams{
		Subject: "https://le.example.org", JWKS: jwksFor(t, "sub-key", generateKey(t)),
	}); err == nil {
		t.Fatal("SubordinateStatement(invalid algorithm) = nil error, want error")
	}
}

func TestSubordinateStatementRejectsEmptyJWKS(t *testing.T) {
	s, err := federation.NewSubordinateIssuer(validSubordinateIssueConfig(), validSubordinateIssueDeps(t))
	if err != nil {
		t.Fatalf("NewSubordinateIssuer: %v", err)
	}
	if _, err := s.SubordinateStatement(federation.SubordinateStatementParams{Subject: "https://le.example.org"}); err == nil {
		t.Fatal("SubordinateStatement(empty jwks) = nil error, want error")
	}
}

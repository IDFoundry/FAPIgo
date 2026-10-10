package server_test

import (
	"context"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// fieldWrappedIssuer is an application's own AccessTokenIssuer holding
// JWTAccessTokens in a named field rather than embedding it, so it has no
// way into the server's checks except AccessTokenIssuerAssurance.
type fieldWrappedIssuer struct {
	inner    server.JWTAccessTokens
	declared *server.AccessTokenAssurance
}

func (w fieldWrappedIssuer) IssueAccessToken(ctx context.Context, p server.AccessTokenParams) (string, string, error) {
	return w.inner.IssueAccessToken(ctx, p)
}

// declaringIssuer adds AccessTokenIssuerAssurance to fieldWrappedIssuer.
type declaringIssuer struct{ fieldWrappedIssuer }

func (d declaringIssuer) AccessTokenAssurance() server.AccessTokenAssurance { return *d.declared }

// embeddingIssuer embeds JWTAccessTokens, as a wrapper adding claims or
// metrics might.
type embeddingIssuer struct{ server.JWTAccessTokens }

func productionNew(t *testing.T, mutate func(*server.Dependencies)) error {
	t.Helper()
	cfg := validConfig(t)
	asProduction(&cfg)
	cfg.Deployment = server.DeploymentSingleInstance
	deps := validDependencies()
	deps.Audit = &fakeAuditSink{}
	mutate(&deps)
	_, err := server.New(cfg, deps)
	return err
}

// TestProductionChecksPointerOpaqueAccessTokens covers
// *OpaqueAccessTokens, which a value-type check let through unchecked.
func TestProductionChecksPointerOpaqueAccessTokens(t *testing.T) {
	err := productionNew(t, func(d *server.Dependencies) {
		d.AccessTokens = &server.OpaqueAccessTokens{Store: memstore.NewAccessTokenStore()}
	})
	if err == nil || !strings.Contains(err.Error(), "access_tokens") {
		t.Fatalf("New(production, *OpaqueAccessTokens over memstore) = %v, want the store refused", err)
	}
	if err := productionNew(t, func(d *server.Dependencies) {
		d.AccessTokens = &server.OpaqueAccessTokens{Store: capAccessTokenStore{caps: storage.Capabilities{Durable: true}}}
	}); err != nil {
		t.Fatalf("New(production, *OpaqueAccessTokens over a durable store): %v", err)
	}
	cfg := validConfig(t)
	deps := validDependencies()
	deps.AccessTokens = &server.OpaqueAccessTokens{Store: memstore.NewAccessTokenStore()}
	if _, err := server.New(cfg, deps); err != nil {
		t.Fatalf("New(development, *OpaqueAccessTokens over memstore): %v", err)
	}
}

// TestProductionChecksCustomAccessTokenIssuers covers an issuer the
// server can't see into: refused under production unless it declares
// what it relies on, which is then checked.
func TestProductionChecksCustomAccessTokenIssuers(t *testing.T) {
	jwt := server.JWTAccessTokens{Keys: newTestKeyManager(), Algorithm: fapi.ES256}
	undeclaredKeys := server.JWTAccessTokens{Keys: undeclaredKeyManager{inner: newTestKeyManager()}, Algorithm: fapi.ES256}
	for name, tc := range map[string]struct {
		issuer  server.AccessTokenIssuer
		wantErr bool
	}{
		"undeclared custom issuer":            {fieldWrappedIssuer{inner: jwt}, true},
		"declares keys with custody":          {declaringIssuer{fieldWrappedIssuer{inner: jwt, declared: &server.AccessTokenAssurance{SigningKeys: jwt.Keys}}}, false},
		"declares keys without custody":       {declaringIssuer{fieldWrappedIssuer{inner: undeclaredKeys, declared: &server.AccessTokenAssurance{SigningKeys: undeclaredKeys.Keys}}}, true},
		"declares a store without assurance":  {declaringIssuer{fieldWrappedIssuer{inner: jwt, declared: &server.AccessTokenAssurance{Store: memstore.NewAccessTokenStore()}}}, true},
		"declares nothing":                    {declaringIssuer{fieldWrappedIssuer{inner: jwt, declared: &server.AccessTokenAssurance{}}}, true},
		"embeds JWTAccessTokens with custody": {embeddingIssuer{jwt}, false},
		"embeds JWTAccessTokens without":      {embeddingIssuer{undeclaredKeys}, true},
		"pointer JWTAccessTokens without":     {&undeclaredKeys, true},
		"nil *JWTAccessTokens":                {(*server.JWTAccessTokens)(nil), true},
		"nil *OpaqueAccessTokens":             {(*server.OpaqueAccessTokens)(nil), true},
	} {
		t.Run(name, func(t *testing.T) {
			err := productionNew(t, func(d *server.Dependencies) { d.AccessTokens = tc.issuer })
			if (err != nil) != tc.wantErr {
				t.Fatalf("New(production) = %v, want error %v", err, tc.wantErr)
			}
		})
	}
}

// TestProductionAcceptsPointerNoRevocation covers &NoRevocation{}, which
// declines revocation as NoRevocation{} does.
func TestProductionAcceptsPointerNoRevocation(t *testing.T) {
	if err := productionNew(t, func(d *server.Dependencies) { d.Revocation = &server.NoRevocation{} }); err != nil {
		t.Fatalf("New(production, &NoRevocation{}): %v", err)
	}
}

// bareAttesterKeys is an AttesterKeySource declaring no
// KeySourceAssurance.
type bareAttesterKeys struct{}

func (bareAttesterKeys) ResolveAttesterKeys(context.Context, keys.AttesterKeyRequest) (keys.VerificationKeySet, error) {
	return keys.VerificationKeySet{}, nil
}

// TestProductionChecksAttesterKeySource covers RegisteredAttesterKeys'
// key source getting the same KeySourceAssurance check as ClientKeys
// when attestation is enabled, by value or pointer.
func TestProductionChecksAttesterKeySource(t *testing.T) {
	for name, tc := range map[string]struct {
		trust   server.AttesterTrust
		wantErr bool
	}{
		"static keys":            {server.RegisteredAttesterKeys{Keys: keys.StaticAttesterKeys{}}, false},
		"undeclared":             {server.RegisteredAttesterKeys{Keys: bareAttesterKeys{}}, true},
		"undeclared, by pointer": {&server.RegisteredAttesterKeys{Keys: bareAttesterKeys{}}, true},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := validAttestationConfig(t)
			asProduction(&cfg)
			cfg.Deployment = server.DeploymentSingleInstance
			deps := validDependencies()
			deps.Audit = &fakeAuditSink{}
			deps.AttesterTrust = tc.trust
			_, err := server.New(cfg, deps)
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("New: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "attester_trust keys") {
				t.Fatalf("New error = %v, want the attester key source refused", err)
			}
		})
	}
	// With attestation disabled, AttesterTrust plays no part.
	if err := productionNew(t, func(d *server.Dependencies) {
		d.AttesterTrust = server.RegisteredAttesterKeys{Keys: bareAttesterKeys{}}
	}); err != nil {
		t.Fatalf("New(production, attestation disabled): %v", err)
	}
}

// bareTrustAnchors and bareAnchorSource are attester trust-anchor
// sources declaring no KeySourceAssurance, as a custom trust list
// fetched by the application's own code would.
type bareTrustAnchors struct{}

func (bareTrustAnchors) TrustAnchors(context.Context, storage.RegisteredClient) (*x509.CertPool, error) {
	return x509.NewCertPool(), nil
}

type bareAnchorSource struct{}

func (bareAnchorSource) AttesterAnchors(context.Context, storage.RegisteredClient) ([]server.AttesterAnchor, error) {
	return nil, nil
}

// unhardenedAnchorSource declares, but not LiveFetchHardened.
type unhardenedAnchorSource struct{ bareAnchorSource }

func (unhardenedAnchorSource) Capabilities() keys.KeySourceCapabilities {
	return keys.KeySourceCapabilities{}
}

// TestProductionChecksAttesterTrustAnchors covers X5CAttesterChain's
// trust-anchor source getting the same KeySourceAssurance check as
// RegisteredAttesterKeys' key source, under each binding mode, by value
// or pointer; the bundled static sources declare it.
func TestProductionChecksAttesterTrustAnchors(t *testing.T) {
	root := newTestCert(t, "attester CA", certOptions{isCA: true})
	for name, tc := range map[string]struct {
		trust server.AttesterTrust
		want  string // "" accepts
	}{
		"static trust anchors": {server.X5CAttesterChain{
			TrustAnchors: server.StaticAttesterTrustAnchors{Roots: poolOf(root)}, IssuerBinding: server.AttesterIssuerInCertificate,
		}, ""},
		"static bound anchors": {server.X5CAttesterChain{
			Anchors: server.StaticAttesterAnchors{{Certificate: root.cert, Issuers: []string{testAttesterIssuer}}}, IssuerBinding: server.AttesterIssuerBoundToAnchor,
		}, ""},
		"undeclared trust anchors": {server.X5CAttesterChain{
			TrustAnchors: bareTrustAnchors{}, IssuerBinding: server.AttesterIssuerInCertificate,
		}, "attester_trust trust_anchors must implement keys.KeySourceAssurance"},
		"undeclared trust anchors, by pointer": {&server.X5CAttesterChain{
			TrustAnchors: bareTrustAnchors{}, IssuerBinding: server.AttesterIssuerByTrustAnchors,
		}, "attester_trust trust_anchors must implement keys.KeySourceAssurance"},
		"undeclared bound anchors": {server.X5CAttesterChain{
			Anchors: bareAnchorSource{}, IssuerBinding: server.AttesterIssuerBoundToAnchor,
		}, "attester_trust anchors must implement keys.KeySourceAssurance"},
		"bound anchors not hardened": {server.X5CAttesterChain{
			Anchors: unhardenedAnchorSource{}, IssuerBinding: server.AttesterIssuerBoundToAnchor,
		}, "attester_trust anchors must declare LiveFetchHardened"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := validAttestationConfig(t)
			asProduction(&cfg)
			cfg.Deployment = server.DeploymentSingleInstance
			deps := validDependencies()
			deps.Audit = &fakeAuditSink{}
			deps.AttesterTrust = tc.trust
			_, err := server.New(cfg, deps)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("New: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("New error = %v, want it to contain %q", err, tc.want)
			}
		})
	}

	t.Run("development accepts an undeclared source", func(t *testing.T) {
		cfg := validAttestationConfig(t)
		deps := validDependencies()
		deps.AttesterTrust = server.X5CAttesterChain{TrustAnchors: bareTrustAnchors{}, IssuerBinding: server.AttesterIssuerInCertificate}
		if _, err := server.New(cfg, deps); err != nil {
			t.Fatalf("New(development): %v", err)
		}
	})
}

// TestNewEnforcesFAPILimitsUnderProduction covers the FAPI 2.0 Security
// Profile's fixed numbers: each out-of-range Limits field is refused
// under AssuranceProduction, every violation reported at once, while
// AssuranceDevelopment leaves them to the embedder.
func TestNewEnforcesFAPILimitsUnderProduction(t *testing.T) {
	cases := map[string]struct {
		mutate func(*server.Limits)
		want   string
	}{
		"code lifetime over 60s":       {func(l *server.Limits) { l.AuthorizationCodeLifetime = 61 * time.Second }, "limits.authorization_code_lifetime"},
		"request_uri lifetime of 600s": {func(l *server.Limits) { l.PushedRequestLifetime = 600 * time.Second }, "limits.pushed_request_lifetime"},
		"clock skew under 10s":         {func(l *server.Limits) { l.MaxClockSkew = 9 * time.Second }, "limits.max_clock_skew"},
		"clock skew over 60s":          {func(l *server.Limits) { l.MaxClockSkew = 61 * time.Second }, "limits.max_clock_skew"},
		"request object over 60m":      {func(l *server.Limits) { l.MaxRequestObjectLifetime = 61 * time.Minute }, "limits.max_request_object_lifetime"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg, deps := productionConfigAndDeps(t)
			tc.mutate(&cfg.Limits)
			if _, err := server.New(cfg, deps); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("New(production) = %v, want %s refused", err, tc.want)
			}
			cfg.Assurance = server.AssuranceDevelopment
			if _, err := server.New(cfg, deps); err != nil {
				t.Fatalf("New(development) = %v, want it accepted", err)
			}
		})
	}
	t.Run("RecommendedLimits accepted", func(t *testing.T) {
		cfg, deps := productionConfigAndDeps(t)
		cfg.Limits = server.RecommendedLimits()
		if _, err := server.New(cfg, deps); err != nil {
			t.Fatalf("New(production, RecommendedLimits) = %v", err)
		}
	})
	t.Run("every violation reported", func(t *testing.T) {
		cfg, deps := productionConfigAndDeps(t)
		cfg.Limits.AuthorizationCodeLifetime = time.Hour
		cfg.Limits.MaxClockSkew = 0
		_, err := server.New(cfg, deps)
		for _, want := range []string{"limits.authorization_code_lifetime", "limits.max_clock_skew"} {
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("New = %v, want it to report %s", err, want)
			}
		}
	})
}

// productionConfigAndDeps is validConfig/validDependencies with every
// AssuranceProduction requirement met.
func productionConfigAndDeps(t *testing.T) (server.Config, server.Dependencies) {
	t.Helper()
	cfg := validConfig(t)
	asProduction(&cfg)
	cfg.Deployment = server.DeploymentSingleInstance
	deps := validDependencies()
	deps.Audit = &fakeAuditSink{}
	if _, err := server.New(cfg, deps); err != nil {
		t.Fatalf("New(production baseline): %v", err)
	}
	return cfg, deps
}

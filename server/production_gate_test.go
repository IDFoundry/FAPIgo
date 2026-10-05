package server_test

import (
	"context"
	"strings"
	"testing"

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
	cfg.Assurance = server.AssuranceProduction
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
	jwt := server.JWTAccessTokens{Keys: &fakeKeyManager{}, Algorithm: fapi.ES256}
	undeclaredKeys := server.JWTAccessTokens{Keys: undeclaredKeyManager{inner: &fakeKeyManager{}}, Algorithm: fapi.ES256}
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
			cfg.Assurance = server.AssuranceProduction
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

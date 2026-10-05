package resource_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// fullCaps is what a production store declares when it is shared across
// instances.
var fullCaps = storage.Capabilities{Durable: true, AtomicConsume: true, CrossInstanceConsistent: true}

type declaredKeys struct {
	fakeIssuerKeySource
	hardened bool
}

func (d *declaredKeys) Capabilities() keys.KeySourceCapabilities {
	return keys.KeySourceCapabilities{LiveFetchHardened: d.hardened}
}

type declaredReplay struct {
	fakeReplayStore
	caps storage.Capabilities
}

func (d *declaredReplay) Capabilities() storage.Capabilities { return d.caps }

type declaredNonces struct {
	*memstore.NonceStore
	caps storage.Capabilities
}

func (d declaredNonces) Capabilities() storage.Capabilities { return d.caps }

type declaredAccessTokens struct {
	*memstore.AccessTokenStore
	caps storage.Capabilities
}

func (d declaredAccessTokens) Capabilities() storage.Capabilities { return d.caps }

type declaredRevocation struct {
	fakeRevocationChecker
	caps storage.Capabilities
}

func (d *declaredRevocation) Capabilities() storage.Capabilities { return d.caps }

// customResolver is an application's own AccessTokenResolver; declared
// makes it implement AccessTokenResolverAssurance.
type customResolver struct{}

func (customResolver) ResolveAccessToken(context.Context, resource.ResolveAccessTokenRequest) (resource.ResolvedAccessToken, error) {
	return resource.ResolvedAccessToken{}, nil
}

type declaringResolver struct {
	customResolver
	declared resource.AccessTokenAssurance
}

func (d declaringResolver) AccessTokenAssurance() resource.AccessTokenAssurance { return d.declared }

func jwtResolver(t *testing.T, source keys.IssuerKeySource) resource.JWTAccessTokens {
	t.Helper()
	issuer, err := fapi.ParseIssuerURL(testIssuer)
	if err != nil {
		t.Fatal(err)
	}
	r, err := resource.NewJWTAccessTokens(source, issuer, testIssuer, fapi.ES256, 5*time.Minute, 8)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// productionSetup is a configuration AssuranceProduction accepts, with
// HorizontallyScaled, nonces and a revocation store, so each case below
// breaks exactly one requirement.
func productionSetup(t *testing.T) (resource.Config, resource.Dependencies) {
	cfg := validConfig(t)
	cfg.Assurance = resource.AssuranceProduction
	cfg.HorizontallyScaled = true
	cfg.Limits.DPoPNonceLifetime = time.Minute
	return cfg, resource.Dependencies{
		AccessTokens: jwtResolver(t, &declaredKeys{hardened: true}),
		Replay:       &declaredReplay{caps: fullCaps},
		Revocation:   &declaredRevocation{caps: fullCaps},
		Clock:        fixedClock{now: time.Now()},
		Nonces:       declaredNonces{NonceStore: memstore.NewNonceStore(), caps: fullCaps},
		Random:       rand.Reader,
	}
}

func TestNewVerifierRequiresAssuranceLevel(t *testing.T) {
	for _, level := range []resource.AssuranceLevel{0, resource.AssuranceProduction + 1} {
		cfg := validConfig(t)
		cfg.Assurance = level
		_, err := resource.NewVerifier(cfg, resource.Dependencies{
			AccessTokens: jwtResolver(t, &fakeIssuerKeySource{}),
			Replay:       &fakeReplayStore{},
			Revocation:   &fakeRevocationChecker{},
			Clock:        fixedClock{now: time.Now()},
		})
		if err == nil || !strings.Contains(err.Error(), "assurance level is invalid") {
			t.Errorf("NewVerifier(assurance %d) = %v, want the assurance level refused", level, err)
		}
	}
}

// TestNewVerifierDevelopmentAcceptsUndeclared: development accepts
// stores and key sources that declare nothing.
func TestNewVerifierDevelopmentAcceptsUndeclared(t *testing.T) {
	cfg := validConfig(t)
	cfg.Limits.DPoPNonceLifetime = time.Minute
	cfg.HorizontallyScaled = true
	if _, err := resource.NewVerifier(cfg, resource.Dependencies{
		AccessTokens: resource.OpaqueAccessTokens{Store: memstore.NewAccessTokenStore()},
		Replay:       &fakeReplayStore{},
		Revocation:   &fakeRevocationChecker{},
		Clock:        fixedClock{now: time.Now()},
		Nonces:       memstore.NewNonceStore(),
		Random:       bytes.NewReader(make([]byte, 64)),
	}); err != nil {
		t.Fatalf("NewVerifier(development) = %v, want accepted", err)
	}
}

func TestNewVerifierProductionAccepts(t *testing.T) {
	for _, tc := range []struct {
		name   string
		modify func(*resource.Config, *resource.Dependencies)
	}{
		{"baseline", func(*resource.Config, *resource.Dependencies) {}},
		{"no revocation", func(_ *resource.Config, d *resource.Dependencies) { d.Revocation = resource.NoRevocation{} }},
		{"no revocation pointer", func(_ *resource.Config, d *resource.Dependencies) { d.Revocation = &resource.NoRevocation{} }},
		{"no nonces, any random", func(_ *resource.Config, d *resource.Dependencies) {
			d.Nonces = nil
			d.Random = bytes.NewReader(nil)
		}},
		{"single instance without CrossInstanceConsistent", func(c *resource.Config, d *resource.Dependencies) {
			c.HorizontallyScaled = false
			caps := storage.Capabilities{Durable: true, AtomicConsume: true}
			d.Replay = &declaredReplay{caps: caps}
			d.Revocation = &declaredRevocation{caps: storage.Capabilities{Durable: true}}
			d.Nonces = declaredNonces{NonceStore: memstore.NewNonceStore(), caps: caps}
		}},
		{"opaque", func(_ *resource.Config, d *resource.Dependencies) {
			d.AccessTokens = resource.OpaqueAccessTokens{Store: declaredAccessTokens{AccessTokenStore: memstore.NewAccessTokenStore(), caps: fullCaps}}
		}},
		{"opaque pointer", func(_ *resource.Config, d *resource.Dependencies) {
			d.AccessTokens = &resource.OpaqueAccessTokens{Store: declaredAccessTokens{AccessTokenStore: memstore.NewAccessTokenStore(), caps: fullCaps}}
		}},
		{"jwt pointer", func(_ *resource.Config, d *resource.Dependencies) {
			r := jwtResolver(t, &declaredKeys{hardened: true})
			d.AccessTokens = &r
		}},
		{"custom resolver declaring keys", func(_ *resource.Config, d *resource.Dependencies) {
			d.AccessTokens = declaringResolver{declared: resource.AccessTokenAssurance{IssuerKeys: &declaredKeys{hardened: true}}}
		}},
		{"custom resolver declaring a store", func(_ *resource.Config, d *resource.Dependencies) {
			d.AccessTokens = declaringResolver{declared: resource.AccessTokenAssurance{Store: declaredAccessTokens{caps: fullCaps}}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, deps := productionSetup(t)
			tc.modify(&cfg, &deps)
			if _, err := resource.NewVerifier(cfg, deps); err != nil {
				t.Fatalf("NewVerifier = %v, want accepted", err)
			}
		})
	}
}

func TestNewVerifierProductionRefuses(t *testing.T) {
	notAtomic := storage.Capabilities{Durable: true, CrossInstanceConsistent: true}
	notDurable := storage.Capabilities{AtomicConsume: true, CrossInstanceConsistent: true}
	notShared := storage.Capabilities{Durable: true, AtomicConsume: true}
	for _, tc := range []struct {
		name   string
		modify func(*resource.Config, *resource.Dependencies)
		want   string
	}{
		{"issuer keys undeclared", func(_ *resource.Config, d *resource.Dependencies) {
			d.AccessTokens = jwtResolver(t, &fakeIssuerKeySource{})
		}, "access_tokens issuer keys must implement keys.KeySourceAssurance"},
		{"issuer keys not hardened", func(_ *resource.Config, d *resource.Dependencies) {
			d.AccessTokens = jwtResolver(t, &declaredKeys{hardened: false})
		}, "access_tokens issuer keys must declare LiveFetchHardened"},
		{"opaque store undeclared", func(_ *resource.Config, d *resource.Dependencies) {
			d.AccessTokens = resource.OpaqueAccessTokens{Store: memstore.NewAccessTokenStore()}
		}, "access_tokens must implement storage.StoreAssurance"},
		{"opaque store not durable", func(_ *resource.Config, d *resource.Dependencies) {
			d.AccessTokens = resource.OpaqueAccessTokens{Store: declaredAccessTokens{AccessTokenStore: memstore.NewAccessTokenStore(), caps: notDurable}}
		}, "access_tokens must declare Durable"},
		{"opaque store not shared", func(_ *resource.Config, d *resource.Dependencies) {
			d.AccessTokens = resource.OpaqueAccessTokens{Store: declaredAccessTokens{AccessTokenStore: memstore.NewAccessTokenStore(), caps: notShared}}
		}, "access_tokens must declare CrossInstanceConsistent"},
		{"nil jwt pointer", func(_ *resource.Config, d *resource.Dependencies) {
			d.AccessTokens = (*resource.JWTAccessTokens)(nil)
		}, "nil *JWTAccessTokens"},
		{"nil opaque pointer", func(_ *resource.Config, d *resource.Dependencies) {
			d.AccessTokens = (*resource.OpaqueAccessTokens)(nil)
		}, "nil *OpaqueAccessTokens"},
		{"custom resolver undeclared", func(_ *resource.Config, d *resource.Dependencies) {
			d.AccessTokens = customResolver{}
		}, "implement resource.AccessTokenResolverAssurance"},
		{"custom resolver declaring nothing", func(_ *resource.Config, d *resource.Dependencies) {
			d.AccessTokens = declaringResolver{}
		}, "must name its IssuerKeys or Store"},
		{"custom resolver's keys undeclared", func(_ *resource.Config, d *resource.Dependencies) {
			d.AccessTokens = declaringResolver{declared: resource.AccessTokenAssurance{IssuerKeys: &fakeIssuerKeySource{}}}
		}, "access_tokens issuer keys must implement keys.KeySourceAssurance"},
		{"custom resolver's store not durable", func(_ *resource.Config, d *resource.Dependencies) {
			d.AccessTokens = declaringResolver{declared: resource.AccessTokenAssurance{Store: declaredAccessTokens{caps: notDurable}}}
		}, "access_tokens must declare Durable"},
		{"replay undeclared", func(_ *resource.Config, d *resource.Dependencies) {
			d.Replay = &fakeReplayStore{}
		}, "replay must implement storage.StoreAssurance"},
		{"replay not durable", func(_ *resource.Config, d *resource.Dependencies) {
			d.Replay = &declaredReplay{caps: notDurable}
		}, "replay must declare Durable"},
		{"replay not atomic", func(_ *resource.Config, d *resource.Dependencies) {
			d.Replay = &declaredReplay{caps: notAtomic}
		}, "replay must declare AtomicConsume"},
		{"replay not shared", func(_ *resource.Config, d *resource.Dependencies) {
			d.Replay = &declaredReplay{caps: notShared}
		}, "replay must declare CrossInstanceConsistent"},
		{"nonces undeclared", func(_ *resource.Config, d *resource.Dependencies) {
			d.Nonces = memstore.NewNonceStore()
		}, "nonces must implement storage.StoreAssurance"},
		{"nonces not durable", func(_ *resource.Config, d *resource.Dependencies) {
			d.Nonces = declaredNonces{NonceStore: memstore.NewNonceStore(), caps: notDurable}
		}, "nonces must declare Durable"},
		{"nonces not atomic", func(_ *resource.Config, d *resource.Dependencies) {
			d.Nonces = declaredNonces{NonceStore: memstore.NewNonceStore(), caps: notAtomic}
		}, "nonces must declare AtomicConsume"},
		{"nonces not shared", func(_ *resource.Config, d *resource.Dependencies) {
			d.Nonces = declaredNonces{NonceStore: memstore.NewNonceStore(), caps: notShared}
		}, "nonces must declare CrossInstanceConsistent"},
		{"random not crypto/rand", func(_ *resource.Config, d *resource.Dependencies) {
			d.Random = bytes.NewReader(make([]byte, 64))
		}, "random must be crypto/rand.Reader"},
		{"revocation undeclared", func(_ *resource.Config, d *resource.Dependencies) {
			d.Revocation = &fakeRevocationChecker{}
		}, "revocation must implement storage.StoreAssurance"},
		{"revocation not durable", func(_ *resource.Config, d *resource.Dependencies) {
			d.Revocation = &declaredRevocation{caps: notDurable}
		}, "revocation must declare Durable"},
		{"revocation not shared", func(_ *resource.Config, d *resource.Dependencies) {
			d.Revocation = &declaredRevocation{caps: notShared}
		}, "revocation must declare CrossInstanceConsistent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, deps := productionSetup(t)
			tc.modify(&cfg, &deps)
			_, err := resource.NewVerifier(cfg, deps)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("NewVerifier = %v, want an error containing %q", err, tc.want)
			}
		})
	}
}

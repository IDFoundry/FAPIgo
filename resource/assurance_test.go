package resource_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"net/http"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
	"io"
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

// undeclaredClock is a Clock that doesn't declare
// resource.ClockAssurance.
type undeclaredClock struct{ now time.Time }

func (c undeclaredClock) Now() time.Time { return c.now }

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
// DeploymentHorizontallyScaled, nonces and a revocation store, so each case below
// breaks exactly one requirement.
func productionSetup(t *testing.T) (resource.Config, resource.Dependencies) {
	cfg := validConfig(t)
	cfg.Assurance = resource.AssuranceProduction
	cfg.Deployment = resource.DeploymentHorizontallyScaled
	cfg.Limits.DPoPNonceLifetime = time.Minute
	cfg.Limits.MaxClockSkew = 10 * time.Second
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
	cfg.Deployment = resource.DeploymentHorizontallyScaled
	if _, err := resource.NewVerifier(cfg, resource.Dependencies{
		AccessTokens: resource.OpaqueAccessTokens{Issuer: testIssuerURL, Store: memstore.NewAccessTokenStore()},
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
		{"no revocation until expiry", func(_ *resource.Config, d *resource.Dependencies) {
			d.Revocation = resource.NoRevocationUntilExpiry{MaxTokenLifetime: 15 * time.Minute}
		}},
		{"no revocation until expiry pointer", func(_ *resource.Config, d *resource.Dependencies) {
			d.Revocation = &resource.NoRevocationUntilExpiry{MaxTokenLifetime: time.Minute}
		}},
		{"DPoP limits at their bounds", func(c *resource.Config, _ *resource.Dependencies) {
			c.Limits.MaxDPoPProofAge = 5 * time.Minute
			c.Limits.DPoPNonceLifetime = 15 * time.Minute
		}},
		{"SystemClock", func(_ *resource.Config, d *resource.Dependencies) { d.Clock = resource.SystemClock{} }},
		{"declared clock 5s behind", func(_ *resource.Config, d *resource.Dependencies) {
			d.Clock = fixedClock{now: time.Now().Add(-5 * time.Second)}
		}},
		{"NoDPoPNonces, any random, no nonce lifetime", func(c *resource.Config, d *resource.Dependencies) {
			d.Nonces = resource.NoDPoPNonces{}
			d.Random = bytes.NewReader(nil)
			c.Limits.DPoPNonceLifetime = 0
		}},
		{"*NoDPoPNonces, no random", func(_ *resource.Config, d *resource.Dependencies) {
			d.Nonces = &resource.NoDPoPNonces{}
			d.Random = nil
		}},
		{"single instance without CrossInstanceConsistent", func(c *resource.Config, d *resource.Dependencies) {
			c.Deployment = resource.DeploymentSingleInstance
			caps := storage.Capabilities{Durable: true, AtomicConsume: true}
			d.Replay = &declaredReplay{caps: caps}
			d.Revocation = &declaredRevocation{caps: storage.Capabilities{Durable: true}}
			d.Nonces = declaredNonces{NonceStore: memstore.NewNonceStore(), caps: caps}
		}},
		{"opaque", func(_ *resource.Config, d *resource.Dependencies) {
			d.AccessTokens = resource.OpaqueAccessTokens{Issuer: testIssuerURL, Store: declaredAccessTokens{AccessTokenStore: memstore.NewAccessTokenStore(), caps: fullCaps}, Audience: "https://rs.example.com"}
		}},
		{"opaque pointer", func(_ *resource.Config, d *resource.Dependencies) {
			d.AccessTokens = &resource.OpaqueAccessTokens{Issuer: testIssuerURL, Store: declaredAccessTokens{AccessTokenStore: memstore.NewAccessTokenStore(), caps: fullCaps}, Audience: "https://rs.example.com"}
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
			d.AccessTokens = resource.OpaqueAccessTokens{Issuer: testIssuerURL, Store: memstore.NewAccessTokenStore()}
		}, "access_tokens must implement storage.StoreAssurance"},
		{"opaque store not durable", func(_ *resource.Config, d *resource.Dependencies) {
			d.AccessTokens = resource.OpaqueAccessTokens{Issuer: testIssuerURL, Store: declaredAccessTokens{AccessTokenStore: memstore.NewAccessTokenStore(), caps: notDurable}}
		}, "access_tokens must declare Durable"},
		{"opaque store not shared", func(_ *resource.Config, d *resource.Dependencies) {
			d.AccessTokens = resource.OpaqueAccessTokens{Issuer: testIssuerURL, Store: declaredAccessTokens{AccessTokenStore: memstore.NewAccessTokenStore(), caps: notShared}}
		}, "access_tokens must declare CrossInstanceConsistent"},
		{"opaque without an audience", func(_ *resource.Config, d *resource.Dependencies) {
			d.AccessTokens = resource.OpaqueAccessTokens{Issuer: testIssuerURL, Store: declaredAccessTokens{AccessTokenStore: memstore.NewAccessTokenStore(), caps: fullCaps}}
		}, "OpaqueAccessTokens.Audience is required"},
		{"opaque pointer without an audience", func(_ *resource.Config, d *resource.Dependencies) {
			d.AccessTokens = &resource.OpaqueAccessTokens{Issuer: testIssuerURL, Store: declaredAccessTokens{AccessTokenStore: memstore.NewAccessTokenStore(), caps: fullCaps}}
		}, "OpaqueAccessTokens.Audience is required"},
		{"no nonces", func(_ *resource.Config, d *resource.Dependencies) {
			d.Nonces = nil
		}, "nonces is required under AssuranceProduction (pass a storage.NonceStore, with Random and Limits.DPoPNonceLifetime, to challenge DPoP proofs for a nonce, or NoDPoPNonces{} to explicitly decline)"},
		{"nil *NoDPoPNonces", func(_ *resource.Config, d *resource.Dependencies) {
			d.Nonces = (*resource.NoDPoPNonces)(nil)
		}, "nonces is a nil *NoDPoPNonces"},
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
		{"no revocation", func(_ *resource.Config, d *resource.Dependencies) {
			d.Revocation = resource.NoRevocation{}
		}, "revocation is NoRevocation, which AssuranceProduction refuses"},
		{"no revocation pointer", func(_ *resource.Config, d *resource.Dependencies) {
			d.Revocation = &resource.NoRevocation{}
		}, "revocation is NoRevocation, which AssuranceProduction refuses"},
		{"no revocation until expiry over 15m", func(_ *resource.Config, d *resource.Dependencies) {
			d.Revocation = resource.NoRevocationUntilExpiry{MaxTokenLifetime: 15*time.Minute + time.Second}
		}, "MaxTokenLifetime must be at most 15m0s"},
		{"DPoP proof age over 5m", func(c *resource.Config, _ *resource.Dependencies) {
			c.Limits.MaxDPoPProofAge = 5*time.Minute + time.Second
		}, "limits.max_dpop_proof_age must be at most 5m0s"},
		{"DPoP proof age of 30 days", func(c *resource.Config, _ *resource.Dependencies) {
			c.Limits.MaxDPoPProofAge = 30 * 24 * time.Hour
		}, "limits.max_dpop_proof_age must be at most 5m0s"},
		{"DPoP nonce lifetime over 15m", func(c *resource.Config, _ *resource.Dependencies) {
			c.Limits.DPoPNonceLifetime = 15*time.Minute + time.Second
		}, "limits.dpop_nonce_lifetime must be at most 15m0s"},
		{"undeclared clock", func(_ *resource.Config, d *resource.Dependencies) {
			d.Clock = undeclaredClock{now: time.Now()}
		}, "clock must be SystemClock, or declare resource.ClockAssurance"},
		{"frozen clock", func(_ *resource.Config, d *resource.Dependencies) {
			d.Clock = fixedClock{now: time.Now().Add(-time.Hour)}
		}, "away from the system's time"},
		{"zero-time clock", func(_ *resource.Config, d *resource.Dependencies) {
			d.Clock = fixedClock{}
		}, "away from the system's time"},
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

// TestNewVerifierProductionRefusesLoopbackJWKSFetcher: a
// keys.JWKSIssuerKeySource fetching through a fapihttp client with a
// loopback exception, or over a plain http.Client, doesn't declare
// LiveFetchHardened, so production refuses it; one over
// fapihttp.NewClient's client without an exception passes.
func TestNewVerifierProductionRefusesLoopbackJWKSFetcher(t *testing.T) {
	hardened, err := fapihttp.NewClient(fapihttp.RecommendedTransportConfig())
	if err != nil {
		t.Fatalf("fapihttp.NewClient: %v", err)
	}
	for name, tc := range map[string]struct {
		transport fapihttp.HTTPClient
		cfg       fapihttp.Config
		refused   bool
	}{
		"no exceptions":       {hardened, fapihttp.Config{}, false},
		"allow loopback http": {hardened, fapihttp.Config{AllowLoopbackHTTP: true}, true},
		"plain http.Client":   {&http.Client{}, fapihttp.Config{}, true},
	} {
		t.Run(name, func(t *testing.T) {
			tc.cfg.MaxResponseBytes, tc.cfg.RequestTimeout = 1<<16, time.Second
			fetcher, err := fapihttp.New(tc.transport, tc.cfg)
			if err != nil {
				t.Fatalf("fapihttp.New: %v", err)
			}
			jwksURI, err := fapi.ParseEndpointURL("https://issuer.example.com/jwks")
			if err != nil {
				t.Fatalf("ParseEndpointURL: %v", err)
			}
			source, err := keys.NewJWKSIssuerKeySource(fetcher, jwksURI, time.Minute)
			if err != nil {
				t.Fatalf("NewJWKSIssuerKeySource: %v", err)
			}
			cfg, deps := productionSetup(t)
			deps.AccessTokens = jwtResolver(t, source)
			_, err = resource.NewVerifier(cfg, deps)
			if tc.refused {
				if err == nil || !strings.Contains(err.Error(), "LiveFetchHardened") {
					t.Fatalf("NewVerifier(production, JWKS source with %s) error = %v, want it refused", name, err)
				}
			} else if err != nil {
				t.Fatalf("NewVerifier(production, JWKS source with %s): %v", name, err)
			}
		})
	}
}

// TestNewVerifierBoundsClockSkewUnderProduction: production holds
// MaxClockSkew to the 10 to 60 seconds server.New does (FAPI 2.0
// Security Profile §5.3.2.1); development accepts any non-negative one.
func TestNewVerifierBoundsClockSkewUnderProduction(t *testing.T) {
	for skew, ok := range map[time.Duration]bool{
		0: false, 5 * time.Second: false, 10 * time.Second: true, time.Minute: true, 61 * time.Second: false, time.Hour: false,
	} {
		cfg, deps := productionSetup(t)
		cfg.Limits.MaxClockSkew = skew
		_, err := resource.NewVerifier(cfg, deps)
		if ok && err != nil {
			t.Errorf("NewVerifier(production, skew %v): %v", skew, err)
		}
		if !ok && (err == nil || !strings.Contains(err.Error(), "limits.max_clock_skew must be between")) {
			t.Errorf("NewVerifier(production, skew %v) = %v, want the clock skew refusal", skew, err)
		}
		cfg.Assurance = resource.AssuranceDevelopment
		if _, err := resource.NewVerifier(cfg, deps); err != nil {
			t.Errorf("NewVerifier(development, skew %v): %v", skew, err)
		}
	}
}

// TestNewVerifierRequiresDeploymentUnderProduction mirrors server.New's
// rule: zero is refused under production and ignored under development;
// a value outside the two defined is refused under either.
func TestNewVerifierRequiresDeploymentUnderProduction(t *testing.T) {
	cfg, deps := productionSetup(t)
	cfg.Deployment = 0
	if _, err := resource.NewVerifier(cfg, deps); err == nil || !strings.Contains(err.Error(), "deployment is required under AssuranceProduction") {
		t.Fatalf("NewVerifier(production, zero deployment) = %v, want the deployment-required refusal", err)
	}
	cfg.Deployment = resource.DeploymentSingleInstance
	if _, err := resource.NewVerifier(cfg, deps); err != nil {
		t.Fatalf("NewVerifier(production, single instance): %v", err)
	}
	dev := validConfig(t)
	dev.Deployment = 0
	if _, err := resource.NewVerifier(dev, validDependencies(t)); err != nil {
		t.Fatalf("NewVerifier(development, zero deployment): %v", err)
	}
	dev.Deployment = resource.DeploymentHorizontallyScaled + 1
	if _, err := resource.NewVerifier(dev, validDependencies(t)); err == nil || !strings.Contains(err.Error(), "deployment is invalid") {
		t.Fatalf("NewVerifier(out-of-range deployment) = %v, want the invalid refusal", err)
	}
}

// TestNewVerifierReportsEveryProductionRefusal: NewVerifier reports
// every dependency production assurance refuses, not just the first.
func TestNewVerifierReportsEveryProductionRefusal(t *testing.T) {
	cfg, deps := productionSetup(t)
	deps.AccessTokens = jwtResolver(t, &declaredKeys{hardened: false})
	deps.Replay = &declaredReplay{caps: storage.Capabilities{Durable: true}}
	deps.Random = io.MultiReader(rand.Reader)

	_, err := resource.NewVerifier(cfg, deps)
	if err == nil {
		t.Fatal("NewVerifier(production, three refusals) = nil error, want error")
	}
	for _, want := range []string{
		"access_tokens issuer keys must declare LiveFetchHardened",
		"replay must declare AtomicConsume",
		"random must be crypto/rand.Reader",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("NewVerifier error = %q, want it to contain %q", err, want)
		}
	}
}

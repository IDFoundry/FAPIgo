package sqlstore_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/pairwise"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/sqlstore"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// discardAudit is an AuditSink that records nothing: production
// requires one, and what it does isn't this package's concern.
type discardAudit struct{}

func (discardAudit) Record(context.Context, server.AuditEvent) error { return nil }

// productionServer builds a server.New configuration and dependencies
// under AssuranceProduction for deployment, with every store this
// package provides taken from d: CIBA on, with d's
// BackchannelAuthenticationStore; opaque access tokens in its
// AccessTokenStore; and pairwise subjects by default, mapped in its
// PairwiseSubjectStore. What it doesn't provide — signing keys and the
// client key source — are the library's own production-ready ones.
func productionServer(t *testing.T, d *sqlstore.DB, deployment server.Deployment) (server.Config, server.Dependencies) {
	t.Helper()
	url := func(raw string) fapi.URL { return mustURL(t, raw) }
	issuer, err := fapi.ParseIssuerURL("https://as.example")
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var specs []keys.SignerSpec
	for _, purpose := range []keys.SigningPurpose{keys.IDTokenSigning, keys.AccessTokenSigning, keys.UserInfoSigning} {
		specs = append(specs, keys.SignerSpec{Purpose: purpose, Algorithm: fapi.ES256, Signer: key})
	}
	km, err := keys.NewKeyManagerFromSigners(specs, keys.DeclareCustody(keys.KeyCustody{Durable: true, CrossInstanceConsistent: true}))
	if err != nil {
		t.Fatal(err)
	}
	clientKeys, err := keys.NewStaticClientKeys(nil)
	if err != nil {
		t.Fatal(err)
	}
	mapping, err := pairwise.NewMapping(d.PairwiseSubjects())
	if err != nil {
		t.Fatal(err)
	}
	prefix, err := pairwise.NewPrefix("")
	if err != nil {
		t.Fatal(err)
	}
	cfg := server.Config{
		Issuer:   issuer,
		Subjects: server.SubjectConfig{Default: fapi.SubjectTypePairwise, Enforcement: server.SubjectTypesPerClient, Prefix: prefix},
		Endpoints: server.Endpoints{
			Authorization: url("https://as.example/authorize"), Token: url("https://as.example/token"),
			PushedAuthorizationRequest: url("https://as.example/par"), JWKS: url("https://as.example/jwks"),
			BackchannelAuthentication: url("https://as.example/backchannel"),
		},
		Profile:    server.ProfileFAPISecurity,
		Algorithms: server.RecommendedAlgorithms(),
		Limits:     server.RecommendedLimits(),
		Assurance:  server.AssuranceProduction,
		Deployment: deployment,
	}
	cfg.Algorithms.BackchannelAuthenticationRequest = server.AlgorithmSet{fapi.ES256}
	cfg.Limits.BackchannelAuthenticationRequestLifetime = 2 * time.Minute
	cfg.Limits.MaxBackchannelAuthenticationRequestLifetime = 5 * time.Minute
	cfg.Limits.BackchannelAuthenticationPollInterval = 5 * time.Second
	deps := server.Dependencies{
		Clients:                d.Clients(),
		Transactions:           d.Transactions(),
		Grants:                 d.Grants(),
		Replay:                 d.Replay(),
		Nonces:                 d.Nonces(),
		Revocation:             d.Revocation(),
		ClientKeys:             clientKeys,
		Keys:                   km,
		AccessTokens:           server.OpaqueAccessTokens{Store: d.AccessTokens()},
		Backchannel:            d.Backchannel(),
		BackchannelNotifier:    server.NoBackchannelNotifications{},
		PairwiseSubjects:       mapping,
		Audit:                  discardAudit{},
		ClientCertificateTrust: server.ClientCertificateChainVerifiedUpstream{},
		Clock:                  server.SystemClock{},
		Random:                 rand.Reader,
	}
	return cfg, deps
}

// A server whose stores are all this package's passes
// AssuranceProduction's gate: horizontally scaled on PostgreSQL, single
// instance on SQLite. SQLite isn't CrossInstanceConsistent, so a
// horizontally scaled deployment on it is refused — as one on memstore
// is refused outright, which shows the gate is really checking.
func TestProductionServerAcceptsStores(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		d := freshDB(t, dialect)
		deployment := server.DeploymentHorizontallyScaled
		if dialect == sqlstore.SQLite {
			deployment = server.DeploymentSingleInstance
		}
		cfg, deps := productionServer(t, d, deployment)
		if _, err := server.New(cfg, deps); err != nil {
			t.Fatalf("server.New(production, %v, %s stores): %v", deployment, dialect, err)
		}
		if dialect == sqlstore.SQLite {
			cfg.Deployment = server.DeploymentHorizontallyScaled
			_, err := server.New(cfg, deps)
			if err == nil || !strings.Contains(err.Error(), "CrossInstanceConsistent") {
				t.Fatalf("server.New(production, horizontally scaled, SQLite stores) = %v, want CrossInstanceConsistent refused", err)
			}
		}
		checkMemstoreRefused(t, d, deployment)
	})
}

// checkMemstoreRefused checks that swapping any one of the stores for
// memstore's, which declares nothing, fails AssuranceProduction's gate:
// it checks each of them.
func checkMemstoreRefused(t *testing.T, d *sqlstore.DB, deployment server.Deployment) {
	t.Helper()
	for name, swap := range map[string]func(*server.Dependencies){
		"Replay": func(deps *server.Dependencies) { deps.Replay = memstore.NewReplayStore() },
		"AccessTokens": func(deps *server.Dependencies) {
			deps.AccessTokens = server.OpaqueAccessTokens{Store: memstore.NewAccessTokenStore()}
		},
		"Backchannel": func(deps *server.Dependencies) { deps.Backchannel = memstore.NewBackchannelAuthenticationStore() },
		"PairwiseSubjects": func(deps *server.Dependencies) {
			mapping, err := pairwise.NewMapping(memstore.NewPairwiseSubjectStore())
			if err != nil {
				t.Fatal(err)
			}
			deps.PairwiseSubjects = mapping
		},
	} {
		cfg, deps := productionServer(t, d, deployment)
		swap(&deps)
		if _, err := server.New(cfg, deps); err == nil {
			t.Errorf("server.New(production, memstore %s) = nil error, want it refused", name)
		}
	}
}

package sqlstore_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
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
// package provides taken from d. What it doesn't provide yet —
// signing keys and the client key source — are the library's own
// production-ready ones; CIBA, whose BackchannelAuthenticationStore
// isn't here yet, stays off, and access tokens are JWTs, which need no
// AccessTokenStore.
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
	cfg := server.Config{
		Issuer:   issuer,
		Subjects: server.PublicSubjects(),
		Endpoints: server.Endpoints{
			Authorization: url("https://as.example/authorize"), Token: url("https://as.example/token"),
			PushedAuthorizationRequest: url("https://as.example/par"), JWKS: url("https://as.example/jwks"),
		},
		Profile:    server.ProfileFAPISecurity,
		Algorithms: server.RecommendedAlgorithms(),
		Limits:     server.RecommendedLimits(),
		Assurance:  server.AssuranceProduction,
		Deployment: deployment,
	}
	deps := server.Dependencies{
		Clients:                d.Clients(),
		Transactions:           d.Transactions(),
		Grants:                 d.Grants(),
		Replay:                 d.Replay(),
		Nonces:                 d.Nonces(),
		Revocation:             d.Revocation(),
		ClientKeys:             clientKeys,
		Keys:                   km,
		AccessTokens:           server.JWTAccessTokens{Keys: km, Algorithm: fapi.ES256},
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
		_, deps = productionServer(t, d, deployment)
		deps.Replay = memstore.NewReplayStore()
		if _, err := server.New(cfg, deps); err == nil {
			t.Fatal("server.New(production, memstore replay store) = nil error, want it refused")
		}
	})
}

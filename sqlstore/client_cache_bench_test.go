package sqlstore_test

import (
	"context"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/sqlstore"
	"github.com/idfoundry/fapigo/storage"
)

// benchClient registers client "bench" in a fresh DB, with an inline
// JWK Set as a private_key_jwt client has, and returns the client
// repository and ClientKeys.
func benchClient(b *testing.B, dialect sqlstore.Dialect, opts sqlstore.Options) (*sqlstore.ClientRepository, *keys.ClientJWKSSource) {
	b.Helper()
	d := newPlace(b, dialect).migratedWith(opts)
	cfg := keyedClient("bench")
	cfg.AllowedScopes = []string{"openid", "accounts", "payments"}
	cfg.SenderConstrain = storage.SenderConstrainDPoP
	must(b, d.Clients().PutWithKeys(context.Background(), cfg, sqlstore.ClientKeyRegistration{JWKS: clientJWKS(b, "k1")}))
	source, err := d.ClientKeys(nil)
	must(b, err)
	return d.Clients(), source
}

// One request's client lookups, as a PAR makes them: ResolveClient,
// then ClientKeys resolving the client's assertion key.
func BenchmarkClientLookup(b *testing.B) {
	for _, dialect := range dialects() {
		b.Run(dialect.String(), func(b *testing.B) {
			benchmarkClientLookup(b, dialect, sqlstore.Options{})
		})
	}
}

func benchmarkClientLookup(b *testing.B, dialect sqlstore.Dialect, opts sqlstore.Options) {
	repo, source := benchClient(b, dialect, opts)
	ctx := context.Background()
	req := keys.ClientKeyRequest{ClientID: "bench", Algorithm: fapi.ES256}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := repo.ResolveClient(ctx, "bench"); err != nil {
			b.Fatal(err)
		}
		if _, err := source.ResolveVerificationKeys(ctx, req); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkClientLookup with Options.ClientCacheTTL set: no query at
// all within it.
func BenchmarkClientLookupTTL(b *testing.B) {
	for _, dialect := range dialects() {
		b.Run(dialect.String(), func(b *testing.B) {
			benchmarkClientLookup(b, dialect, sqlstore.Options{ClientCacheTTL: time.Hour})
		})
	}
}

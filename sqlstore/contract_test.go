package sqlstore_test

import (
	"context"
	"testing"

	"github.com/idfoundry/fapigo/sqlstore"
	"github.com/idfoundry/fapigo/storage"
)

// Each contract suite runs against each dialect, every factory call a
// migrated handle on tables of its own.

func TestTransactionStoreContract(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		storage.TestTransactionStoreContract(t, func() storage.TransactionStore { return freshDB(t, dialect).Transactions() })
	})
}

func TestGrantStoreContract(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		storage.TestGrantStoreContract(t, func() storage.GrantStore { return freshDB(t, dialect).Grants() })
	})
}

func TestReplayStoreContract(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		storage.TestReplayStoreContract(t, func() storage.ReplayStore { return freshDB(t, dialect).Replay() })
	})
}

func TestNonceStoreContract(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		storage.TestNonceStoreContract(t, func() storage.NonceStore { return freshDB(t, dialect).Nonces() })
	})
}

func TestRevocationStoreContract(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		storage.TestRevocationStoreContract(t, func() storage.RevocationStore { return freshDB(t, dialect).Revocation() })
	})
}

func TestClientRepositoryContract(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		storage.TestClientRepositoryContract(t, func(clients []storage.RegisteredClient) storage.ClientRepository {
			repo := freshDB(t, dialect).Clients()
			for _, c := range clients {
				if err := repo.Put(context.Background(), configOf(c)); err != nil {
					t.Fatalf("Put(%q): %v", c.ID(), err)
				}
			}
			return repo
		})
	})
}

// configOf rebuilds the configuration of c, a client the contract
// suite made, from what RegisteredClient exposes. RegisteredClient
// doesn't list its allowed scopes, so they're not carried over: the
// suite checks which client resolves, not its scopes, and
// TestClientConfigRoundTrips covers every field through Put and
// ResolveClient.
func configOf(c storage.RegisteredClient) storage.RegisteredClientConfig {
	return storage.RegisteredClientConfig{
		ID:                        c.ID(),
		RedirectURIs:              c.RedirectURIs(),
		ApplicationType:           c.ApplicationType(),
		ClientAuthMethods:         c.ClientAuthMethods(),
		ClientAssertionAlgorithms: c.ClientAssertionAlgorithms(),
		SenderConstrain:           c.SenderConstrain(),
		AuthorizationDetailsTypes: c.AuthorizationDetailsTypes(),
		AllowedResources:          c.AllowedResources(),
	}
}

// The stores declare what server.New's production gate checks.
func TestCapabilities(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		d := freshDB(t, dialect)
		want := storage.Capabilities{Durable: true, AtomicConsume: true, CrossInstanceConsistent: true}
		if dialect == sqlstore.SQLite {
			want = storage.Capabilities{Durable: true, AtomicConsume: true, SerializableRedemption: true}
		}
		for name, s := range map[string]storage.StoreAssurance{
			"Clients": d.Clients(), "Transactions": d.Transactions(), "Grants": d.Grants(),
			"Replay": d.Replay(), "Nonces": d.Nonces(), "Revocation": d.Revocation(),
		} {
			if got := s.Capabilities(); got != want {
				t.Errorf("%s().Capabilities() = %+v, want %+v", name, got, want)
			}
		}
	})
}

// Compile-time checks that each store is the interface its accessor
// is for.
var (
	_ storage.ClientRepository = (*sqlstore.ClientRepository)(nil)
	_ storage.TransactionStore = (*sqlstore.TransactionStore)(nil)
	_ storage.GrantStore       = (*sqlstore.GrantStore)(nil)
	_ storage.ReplayStore      = (*sqlstore.ReplayStore)(nil)
	_ storage.NonceStore       = (*sqlstore.NonceStore)(nil)
	_ storage.RevocationStore  = (*sqlstore.RevocationStore)(nil)
)

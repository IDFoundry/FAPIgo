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

func TestAccessTokenStoreContract(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		storage.TestAccessTokenStoreContract(t, func() storage.AccessTokenStore { return freshDB(t, dialect).AccessTokens() })
	})
}

func TestBackchannelAuthenticationStoreContract(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		storage.TestBackchannelAuthenticationStoreContract(t, func() storage.BackchannelAuthenticationStore { return freshDB(t, dialect).Backchannel() })
	})
}

func TestPairwiseSubjectStoreContract(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		storage.TestPairwiseSubjectStoreContract(t, func() storage.PairwiseSubjectStore { return freshDB(t, dialect).PairwiseSubjects() })
	})
}

func TestSessionStoreContract(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		storage.TestSessionStoreContract(t, func() storage.SessionStore { return freshDB(t, dialect).Sessions() })
	})
}

// Every contract suite whose store seals its records passes with a
// Sealer too.
func TestSealedStoreContracts(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		sealed := func() *sqlstore.DB { return newPlace(t, dialect).migratedWith(sqlstore.Options{Sealer: testSealer(t)}) }
		t.Run("Transactions", func(t *testing.T) {
			storage.TestTransactionStoreContract(t, func() storage.TransactionStore { return sealed().Transactions() })
		})
		t.Run("Grants", func(t *testing.T) {
			storage.TestGrantStoreContract(t, func() storage.GrantStore { return sealed().Grants() })
		})
		t.Run("AccessTokens", func(t *testing.T) {
			storage.TestAccessTokenStoreContract(t, func() storage.AccessTokenStore { return sealed().AccessTokens() })
		})
		t.Run("Backchannel", func(t *testing.T) {
			storage.TestBackchannelAuthenticationStoreContract(t, func() storage.BackchannelAuthenticationStore { return sealed().Backchannel() })
		})
		t.Run("Sessions", func(t *testing.T) {
			storage.TestSessionStoreContract(t, func() storage.SessionStore { return sealed().Sessions() })
		})
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

// The stores declare what server.New's production gate checks; with a
// Sealer, those whose records it seals declare EncryptedAtRest too —
// but not while ReadUnsealed accepts records it never sealed.
func TestCapabilities(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		want := storage.Capabilities{Durable: true, AtomicConsume: true, CrossInstanceConsistent: true}
		if dialect == sqlstore.SQLite {
			want = storage.Capabilities{Durable: true, AtomicConsume: true, SerializableRedemption: true}
		}
		encrypted := want
		encrypted.EncryptedAtRest = true
		p := newPlace(t, dialect)
		checkCapabilities(t, p.migrated(), want, want)
		checkCapabilities(t, p.migratedWith(sqlstore.Options{Sealer: testSealer(t)}), want, encrypted)
		checkCapabilities(t, p.migratedWith(sqlstore.Options{Sealer: testSealer(t), ReadUnsealed: true}), want, want)
	})
}

// checkCapabilities checks that d's stores whose records a Sealer seals
// declare sealed, and the rest plain.
func checkCapabilities(t *testing.T, d *sqlstore.DB, plain, sealed storage.Capabilities) {
	t.Helper()
	for name, s := range map[string]storage.StoreAssurance{
		"Clients": d.Clients(), "Replay": d.Replay(), "Nonces": d.Nonces(), "Revocation": d.Revocation(),
		"PairwiseSubjects": d.PairwiseSubjects(),
	} {
		if got := s.Capabilities(); got != plain {
			t.Errorf("%s().Capabilities() = %+v, want %+v", name, got, plain)
		}
	}
	for name, s := range map[string]storage.StoreAssurance{
		"Transactions": d.Transactions(), "Grants": d.Grants(), "AccessTokens": d.AccessTokens(), "Backchannel": d.Backchannel(),
		"Sessions": d.Sessions(),
	} {
		if got := s.Capabilities(); got != sealed {
			t.Errorf("%s().Capabilities() = %+v, want %+v", name, got, sealed)
		}
	}
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

	_ storage.AccessTokenStore               = (*sqlstore.AccessTokenStore)(nil)
	_ storage.BackchannelAuthenticationStore = (*sqlstore.BackchannelAuthenticationStore)(nil)
	_ storage.PairwiseSubjectStore           = (*sqlstore.PairwiseSubjectStore)(nil)
	_ storage.SessionStore                   = (*sqlstore.SessionStore)(nil)
)

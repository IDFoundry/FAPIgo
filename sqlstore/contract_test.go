package sqlstore_test

import (
	"context"
	"testing"
	"time"

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
		t.Run("Plain", func(t *testing.T) {
			storage.TestGrantStoreContract(t, func() storage.GrantStore { return freshDB(t, dialect).Grants() })
		})
		t.Run("Batching", func(t *testing.T) {
			storage.TestGrantStoreContract(t, func() storage.GrantStore { return freshDB(t, dialect).BatchingGrants() })
		})
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
		t.Run("Plain", func(t *testing.T) {
			storage.TestRevocationStoreContract(t, func() storage.RevocationStore { return freshDB(t, dialect).Revocation() })
		})
		t.Run("Batching", func(t *testing.T) {
			storage.TestRevocationStoreContract(t, func() storage.RevocationStore { return freshDB(t, dialect).BatchingRevocation() })
		})
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

func TestInteractionLookupContract(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		storage.TestInteractionLookupContract(t, func() (storage.TransactionStore, storage.InteractionLookup) {
			db := freshDB(t, dialect)
			return db.Transactions(), db.InteractionLookup()
		})
	})
}

// TestPushedRequestLookupContract runs the lookup's storage contract on
// each database, with the TransactionStore of the DB it reads.
func TestPushedRequestLookupContract(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		storage.TestPushedRequestLookupContract(t, func() (storage.TransactionStore, storage.PushedRequestLookup) {
			db := freshDB(t, dialect)
			return db.Transactions(), db.PushedRequestLookup()
		})
	})
}

func TestGrantRegistryContract(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		storage.TestGrantRegistryContract(t, func() storage.GrantRegistry { return freshDB(t, dialect).GrantRegistry() })
	})
}

// TestGrantRegistryListsByKeyAlone checks that a keyed listing reads
// only that entry, not the subject's other grants with it.
func TestGrantRegistryListsByKeyAlone(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		r := freshDB(t, dialect).GrantRegistry()
		ctx := context.Background()
		expires := time.Now().Add(time.Hour)
		for _, key := range []string{"g1", "g2"} {
			if err := r.RecordGrant(ctx, storage.NewGrantEntry{Key: key, SubjectKey: "s1", ClientID: "c", Record: []byte(`{}`), ExpiresAt: expires}); err != nil {
				t.Fatal(err)
			}
		}
		entries, err := r.ListGrants(ctx, storage.GrantListing{SubjectKey: "s1", Now: time.Now(), Key: "g1"})
		if err != nil || len(entries) != 1 || entries[0].Key != "g1" {
			t.Fatalf("ListGrants(s1, key g1) = %+v, %v, want g1 alone", entries, err)
		}
	})
}

func TestBackchannelInboxContract(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		storage.TestBackchannelInboxContract(t, func() storage.BackchannelInbox { return freshDB(t, dialect).BackchannelInbox() })
	})
}

func TestPairwiseSubjectEraserContract(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		storage.TestPairwiseSubjectEraserContract(t, func() storage.PairwiseSubjectEraser { return freshDB(t, dialect).PairwiseSubjects() })
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
		t.Run("GrantRegistry", func(t *testing.T) {
			storage.TestGrantRegistryContract(t, func() storage.GrantRegistry { return sealed().GrantRegistry() })
		})
		t.Run("BackchannelInbox", func(t *testing.T) {
			storage.TestBackchannelInboxContract(t, func() storage.BackchannelInbox { return sealed().BackchannelInbox() })
		})
		t.Run("InteractionLookup", func(t *testing.T) {
			storage.TestInteractionLookupContract(t, func() (storage.TransactionStore, storage.InteractionLookup) {
				db := sealed()
				return db.Transactions(), db.InteractionLookup()
			})
		})
		t.Run("PushedRequestLookup", func(t *testing.T) {
			storage.TestPushedRequestLookupContract(t, func() (storage.TransactionStore, storage.PushedRequestLookup) {
				db := sealed()
				return db.Transactions(), db.PushedRequestLookup()
			})
		})
		t.Run("Grants", func(t *testing.T) {
			storage.TestGrantStoreContract(t, func() storage.GrantStore { return sealed().Grants() })
		})
		t.Run("BatchingGrants", func(t *testing.T) {
			storage.TestGrantStoreContract(t, func() storage.GrantStore { return sealed().BatchingGrants() })
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
		"Sessions":            d.Sessions(),
		"InteractionLookup":   d.InteractionLookup().(storage.StoreAssurance),
		"PushedRequestLookup": d.PushedRequestLookup().(storage.StoreAssurance),
		"GrantRegistry":       d.GrantRegistry().(storage.StoreAssurance),
		"BackchannelInbox":    d.BackchannelInbox().(storage.StoreAssurance),
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

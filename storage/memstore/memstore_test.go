package memstore

import (
	"context"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/storage"
)

func TestTransactionStoreContract(t *testing.T) {
	storage.TestTransactionStoreContract(t, func() storage.TransactionStore {
		return NewTransactionStore()
	})
}

func TestGrantStoreContract(t *testing.T) {
	storage.TestGrantStoreContract(t, func() storage.GrantStore {
		return NewGrantStore()
	})
}

func TestReplayStoreContract(t *testing.T) {
	storage.TestReplayStoreContract(t, func() storage.ReplayStore {
		return NewReplayStore()
	})
}

func newTestClient(t *testing.T, id fapi.ClientID) storage.RegisteredClient {
	t.Helper()
	c, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID:                       id,
		RedirectURIs:             []fapi.RegisteredRedirectURI{"https://rp.example/callback"},
		ClientAssertionAlgorithm: fapi.ES256,
		AllowedScopes:            []string{"openid"},
	})
	if err != nil {
		t.Fatalf("storage.NewRegisteredClient: %v", err)
	}
	return c
}

func TestClientRepositoryResolvesRegisteredClient(t *testing.T) {
	client := newTestClient(t, "client-1")
	repo := NewClientRepository([]storage.RegisteredClient{client})

	got, err := repo.ResolveClient(context.Background(), "client-1")
	if err != nil {
		t.Fatalf("ResolveClient: %v", err)
	}
	if got.ID() != "client-1" {
		t.Fatalf("ID() = %q, want %q", got.ID(), "client-1")
	}
}

func TestClientRepositoryRejectsUnknownClient(t *testing.T) {
	repo := NewClientRepository([]storage.RegisteredClient{newTestClient(t, "client-1")})

	if _, err := repo.ResolveClient(context.Background(), "client-2"); err == nil {
		t.Fatal("ResolveClient(unknown) = nil error, want error")
	}
}

func TestClientRepositoryEmpty(t *testing.T) {
	repo := NewClientRepository(nil)

	if _, err := repo.ResolveClient(context.Background(), "client-1"); err == nil {
		t.Fatal("ResolveClient on empty repository = nil error, want error")
	}
}

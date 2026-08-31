package fapitest

import (
	"testing"

	"github.com/idfoundry/fapigo/storage"
)

// These run the shared storage contract suite against the harness's own
// in-memory reference stores — the same suite a downstream storage
// backend should run against itself; see storage.StoreAssurance.

func TestMemGrantStoreContract(t *testing.T) {
	storage.TestGrantStoreContract(t, func() storage.GrantStore { return newMemGrantStore() })
}

func TestMemTransactionStoreContract(t *testing.T) {
	storage.TestTransactionStoreContract(t, func() storage.TransactionStore { return newMemTransactionStore() })
}

func TestMemReplayStoreContract(t *testing.T) {
	storage.TestReplayStoreContract(t, func() storage.ReplayStore { return newMemReplayStore() })
}

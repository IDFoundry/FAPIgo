package main

import (
	"testing"

	"github.com/idfoundry/fapigo/storage"
)

func TestInMemoryTransactionStoreContract(t *testing.T) {
	storage.TestTransactionStoreContract(t, func() storage.TransactionStore {
		return newInMemoryTransactionStore()
	})
}

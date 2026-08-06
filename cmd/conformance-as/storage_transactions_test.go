package main

import (
	"testing"

	"github.com/osanderson/go-fapi/storage"
)

func TestInMemoryTransactionStoreContract(t *testing.T) {
	storage.TestTransactionStoreContract(t, func() storage.TransactionStore {
		return newInMemoryTransactionStore()
	})
}

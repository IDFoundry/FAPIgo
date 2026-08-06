package main

import (
	"testing"

	"github.com/osanderson/go-fapi/storage"
)

func TestInMemoryGrantStoreContract(t *testing.T) {
	storage.TestGrantStoreContract(t, func() storage.GrantStore {
		return newInMemoryGrantStore()
	})
}

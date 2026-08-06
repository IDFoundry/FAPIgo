package main

import (
	"testing"

	"github.com/osanderson/go-fapi/storage"
)

func TestInMemoryReplayStoreContract(t *testing.T) {
	storage.TestReplayStoreContract(t, func() storage.ReplayStore {
		return newInMemoryReplayStore()
	})
}

package main

import (
	"testing"

	"github.com/idfoundry/fapigo/storage"
)

func TestInMemoryReplayStoreContract(t *testing.T) {
	storage.TestReplayStoreContract(t, func() storage.ReplayStore {
		return newInMemoryReplayStore()
	})
}

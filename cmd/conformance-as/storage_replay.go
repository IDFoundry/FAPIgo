package main

import (
	"context"
	"fmt"
	"sync"

	"github.com/idfoundry/fapigo/storage"
)

// inMemoryReplayStore is an in-memory storage.ReplayStore, ported from
// fapitest/storage.go's memReplayStore — see inMemoryTransactionStore's
// doc comment for the rationale.
type inMemoryReplayStore struct {
	mu   sync.Mutex
	seen map[storage.ReplayNamespace]map[[32]byte]bool
}

func newInMemoryReplayStore() *inMemoryReplayStore {
	return &inMemoryReplayStore{seen: make(map[storage.ReplayNamespace]map[[32]byte]bool)}
}

// UseOnce implements storage.ReplayStore.
func (s *inMemoryReplayStore) UseOnce(_ context.Context, use storage.ReplayUse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	byDigest, ok := s.seen[use.Namespace]
	if !ok {
		byDigest = make(map[[32]byte]bool)
		s.seen[use.Namespace] = byDigest
	}
	if byDigest[use.Digest] {
		return fmt.Errorf("conformance-as: replay detected in namespace %q", use.Namespace)
	}
	byDigest[use.Digest] = true
	return nil
}

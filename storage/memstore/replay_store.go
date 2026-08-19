package memstore

import (
	"context"
	"fmt"
	"sync"

	"github.com/idfoundry/fapigo/storage"
)

// ReplayStore is an in-memory storage.ReplayStore. See the package doc
// comment for why this is development/testing only.
type ReplayStore struct {
	mu   sync.Mutex
	seen map[storage.ReplayNamespace]map[[32]byte]bool
}

// NewReplayStore builds an empty ReplayStore.
func NewReplayStore() *ReplayStore {
	return &ReplayStore{seen: make(map[storage.ReplayNamespace]map[[32]byte]bool)}
}

// UseOnce implements storage.ReplayStore.
func (s *ReplayStore) UseOnce(_ context.Context, use storage.ReplayUse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	byDigest, ok := s.seen[use.Namespace]
	if !ok {
		byDigest = make(map[[32]byte]bool)
		s.seen[use.Namespace] = byDigest
	}
	if byDigest[use.Digest] {
		return fmt.Errorf("memstore: replay detected in namespace %q", use.Namespace)
	}
	byDigest[use.Digest] = true
	return nil
}

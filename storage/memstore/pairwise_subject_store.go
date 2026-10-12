package memstore

import (
	"context"
	"fmt"
	"sync"

	"github.com/idfoundry/fapigo/storage"
)

// PairwiseSubjectStore is an in-memory storage.PairwiseSubjectStore.
// See the package doc comment for why this is development/testing
// only: its mappings are gone on restart, which changes every pairwise
// subject identifier it issued.
type PairwiseSubjectStore struct {
	mu       sync.Mutex
	bodies   map[storage.PairwiseSubjectKey]string
	subjects map[pairwiseBody]string
}

// pairwiseBody indexes a body within its issuer and sector, for Lookup
// and for refusing a body already in use.
type pairwiseBody struct {
	issuer, sector, body string
}

// NewPairwiseSubjectStore builds an empty PairwiseSubjectStore.
func NewPairwiseSubjectStore() *PairwiseSubjectStore {
	return &PairwiseSubjectStore{
		bodies:   make(map[storage.PairwiseSubjectKey]string),
		subjects: make(map[pairwiseBody]string),
	}
}

// GetOrCreate implements storage.PairwiseSubjectStore.
func (s *PairwiseSubjectStore) GetOrCreate(_ context.Context, key storage.PairwiseSubjectKey, candidate string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if body, ok := s.bodies[key]; ok {
		return body, nil
	}
	index := pairwiseBody{key.Issuer, key.Sector, candidate}
	if _, taken := s.subjects[index]; taken {
		return "", fmt.Errorf("memstore: %w", storage.ErrPairwiseSubjectCollision)
	}
	s.bodies[key] = candidate
	s.subjects[index] = key.Subject
	return candidate, nil
}

// Lookup implements storage.PairwiseSubjectStore.
func (s *PairwiseSubjectStore) Lookup(_ context.Context, issuer, sector, body string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	subject, ok := s.subjects[pairwiseBody{issuer, sector, body}]
	if !ok {
		return "", fmt.Errorf("memstore: %w", storage.ErrPairwiseSubjectNotFound)
	}
	return subject, nil
}

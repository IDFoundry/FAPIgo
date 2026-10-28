package memstore

import (
	"context"
	"fmt"
	"sync"

	"github.com/idfoundry/fapigo/storage"
)

// NonceStore is an in-memory storage.NonceStore. See the package doc
// comment for why this is development/testing only.
type NonceStore struct {
	mu     sync.Mutex
	issued map[string]storage.NonceRecord
}

// NewNonceStore builds an empty NonceStore.
func NewNonceStore() *NonceStore {
	return &NonceStore{issued: make(map[string]storage.NonceRecord)}
}

// Issue implements storage.NonceStore.
func (s *NonceStore) Issue(_ context.Context, issuance storage.NonceIssuance) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.issued[issuance.Nonce] = storage.NonceRecord{ExpiresAt: issuance.ExpiresAt}
	return nil
}

// Lookup implements storage.NonceStore. It never removes the record: a
// nonce stays valid, for any number of requests, until the caller finds
// it expired.
func (s *NonceStore) Lookup(_ context.Context, lookup storage.NonceLookup) (storage.NonceRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.issued[lookup.Nonce]
	if !ok {
		return storage.NonceRecord{}, fmt.Errorf("memstore: unknown nonce")
	}
	return record, nil
}

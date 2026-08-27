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

// Consume implements storage.NonceStore. Deleting the map entry on
// every call — whether or not it was present — is what makes this
// single-use: a second Consume of the same nonce always finds nothing.
func (s *NonceStore) Consume(_ context.Context, consumption storage.NonceConsumption) (storage.NonceRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.issued[consumption.Nonce]
	delete(s.issued, consumption.Nonce)
	if !ok {
		return storage.NonceRecord{}, fmt.Errorf("memstore: unknown or already-consumed nonce")
	}
	return record, nil
}

package memstore

import (
	"context"
	"sync"
	"time"
)

// RevocationStore is an in-memory access-token revocation store. It
// satisfies both server.RevocationSink (Revoke) and
// resource.RevocationChecker (IsRevoked) — a deployment typically
// shares one instance between the two, the same way it shares one
// ReplayStore. See the package doc comment for why this is
// development/testing only: a jti is remembered forever, with no
// active expiry sweeping (consistent with the rest of this package).
type RevocationStore struct {
	mu      sync.Mutex
	revoked map[string]time.Time
}

// NewRevocationStore builds an empty RevocationStore.
func NewRevocationStore() *RevocationStore {
	return &RevocationStore{revoked: make(map[string]time.Time)}
}

// Revoke implements server.RevocationSink.
func (s *RevocationStore) Revoke(_ context.Context, jti string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revoked[jti] = expiresAt
	return nil
}

// IsRevoked implements resource.RevocationChecker.
func (s *RevocationStore) IsRevoked(_ context.Context, jti string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.revoked[jti]
	return ok, nil
}

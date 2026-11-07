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
// development/testing only: a key is remembered forever, with no
// active expiry sweeping (consistent with the rest of this package).
//
// Revoke's expiresAt is recorded per key but never consulted here —
// it exists so a real RevocationSink backend (Redis, DynamoDB, a SQL
// row) can use it as a native TTL and self-expire the record once the
// access token's own expiry would have made it invalid regardless of
// revocation (resource.Verify checks the token's own validity before
// ever consulting revocation, so nothing reachable depends on
// pruning). Doing that here too would make this store's memory
// behavior diverge from every sibling in this package, all of which
// keep the same unbounded-growth tradeoff — not worth the
// inconsistency for a store this package doc already says isn't
// meant to run long enough for it to matter.
type RevocationStore struct {
	mu      sync.Mutex
	revoked map[string]time.Time
}

// NewRevocationStore builds an empty RevocationStore.
func NewRevocationStore() *RevocationStore {
	return &RevocationStore{revoked: make(map[string]time.Time)}
}

// Revoke implements server.RevocationSink.
func (s *RevocationStore) Revoke(_ context.Context, key string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revoked[key] = expiresAt
	return nil
}

// IsRevoked implements resource.RevocationChecker.
func (s *RevocationStore) IsRevoked(_ context.Context, key string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.revoked[key]
	return ok, nil
}

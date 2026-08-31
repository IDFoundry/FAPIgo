package main

import (
	"sync"
	"time"

	"github.com/idfoundry/fapigo/server"
)

// pendingSet is a thread-safe, TTL-evicting, single-use map bridging
// two HTTP legs of a begin/complete interaction: Put during the begin
// leg (GET /authorize, POST /backchannel-authenticate), TakeOnce during
// the complete leg (POST /authorize/decision, POST /backchannel-approve).
// A second TakeOnce for the same key always misses — mirroring the
// library's own single-use InteractionHandle/BackchannelAuthenticationHandle
// contract at this HTTP-adapter layer, on top of (not instead of) the
// protocol-level single-use guarantee TransactionStore/GrantStore
// already enforce; deleting the entry here is defense in depth.
//
// An entry whose complete leg never arrives (an abandoned consent
// page, an approval that never comes back) is swept the next time Put
// runs past its own expiry, rather than retained forever — this
// binary is long-running (it serves an entire conformance suite run),
// so an unbounded map would be a real leak, not a theoretical one.
// Piggybacking eviction on Put avoids needing a background goroutine
// (and its own shutdown handling) to manage.
type pendingSet[K comparable, V any] struct {
	mu    sync.Mutex
	clock server.Clock
	items map[K]pendingEntry[V]
}

type pendingEntry[V any] struct {
	value     V
	expiresAt time.Time
}

// newPendingSet builds an empty pendingSet. clock is threaded through
// explicitly rather than calling time.Now directly, mirroring every
// other clock-consuming type in this binary.
func newPendingSet[K comparable, V any](clock server.Clock) *pendingSet[K, V] {
	return &pendingSet[K, V]{clock: clock, items: make(map[K]pendingEntry[V])}
}

// Put stashes value under key, expiring after ttl if TakeOnce is never
// called for it. Also sweeps every already-expired entry first.
func (s *pendingSet[K, V]) Put(key K, value V, ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock.Now()
	for k, entry := range s.items {
		if !now.Before(entry.expiresAt) {
			delete(s.items, k)
		}
	}
	s.items[key] = pendingEntry[V]{value: value, expiresAt: now.Add(ttl)}
}

// TakeOnce retrieves and retires the entry stashed under key — a
// second call with the same key, or a call after its own ttl expired,
// always misses.
func (s *pendingSet[K, V]) TakeOnce(key K) (V, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.items[key]
	if ok {
		delete(s.items, key)
	}
	if !ok || s.clock.Now().After(entry.expiresAt) {
		var zero V
		return zero, false
	}
	return entry.value, true
}

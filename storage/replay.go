package storage

import (
	"context"
	"time"
)

// ReplayNamespace scopes a replayed-use digest to the subsystem that
// recorded it, so different roles and subsystems can never collide on
// the same use-once token even if they happen to hash to the same
// digest (e.g. "server:client-assertion", "server:request-object",
// "server:dpop", "resource:dpop").
type ReplayNamespace string

// ReplayUse is one use-once check: has Digest, scoped to Namespace, been
// seen before.
type ReplayUse struct {
	Namespace ReplayNamespace
	Digest    [32]byte
	ExpiresAt time.Time
}

// ReplayStore records a single-use digest, failing if it has already
// been recorded. Implementations must treat the check and the record as
// one atomic operation — two concurrent UseOnce calls for the same
// digest must never both succeed.
//
// Only a digest is stored, never the value it was derived from — a
// complete client assertion, DPoP proof or request object must not be
// persisted just to detect its reuse.
//
// A recorded digest must be retained until at least its ExpiresAt: the
// server accepts the value it came from until then, so a store that
// forgets it earlier (an LRU, a size cap, a TTL shorter than
// ExpiresAt) lets the same value be replayed. A store may drop entries
// once ExpiresAt has passed.
//
// With a backend's own per-key TTL, set the TTL from the record's
// expiry, never a fixed value: for Redis, SET key 1 NX PXAT with
// ExpiresAt in Unix milliseconds, or PX with time.Until(ExpiresAt)
// rounded up (and at least 1). A fixed TTL shorter than some ExpiresAt —
// a lifetime limit raised later, say — forgets those records early, and
// no contract test can tell: the record is gone only after the test has
// finished checking it.
//
// UseOnce's error means the digest was already recorded, unless it
// wraps ErrStoreUnavailable (the store couldn't answer at all), or
// context.Canceled or context.DeadlineExceeded; a resource server
// answers those with 500 server_error rather than refusing the DPoP
// proof as replayed.
type ReplayStore interface {
	UseOnce(ctx context.Context, use ReplayUse) error
}

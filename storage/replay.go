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
type ReplayStore interface {
	UseOnce(ctx context.Context, use ReplayUse) error
}

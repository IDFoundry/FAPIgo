package storage

import (
	"context"
	"time"
)

// RevocationStore is a store that is both halves of revocation: the
// authorization server's server.RevocationSink (Revoke) and the resource
// server's resource.RevocationChecker (IsRevoked), typically one shared
// instance. It exists for TestRevocationStoreContract; the server and
// resource packages each take only the half they use.
//
// Revoke records key as revoked until at least expiresAt; IsRevoked
// reports true for it until then. Keys are opaque and compared exactly:
// an access token's key (a JWT's jti, an opaque token's hash), a revoked
// grant's ("grant:" and the grant ID), and a reused code's grant
// ("code-grant:" and its ID) share the store, and each must answer only
// for itself. Revoking a key again is not an error and leaves it revoked
// at least until the later expiresAt. A store may forget a key once its
// expiresAt has passed.
//
// With a backend's own per-key TTL, set the TTL from the record's
// expiry, never a fixed value: for Redis, SET key 1 PXAT with expiresAt
// in Unix milliseconds, or PX with time.Until(expiresAt) rounded up (and
// at least 1); on a key already revoked, keep the later expiry. A fixed
// TTL shorter than some expiresAt — a lifetime limit raised later, say —
// forgets those revocations early, and no contract test can tell: the
// record is gone only after the test has finished checking it.
type RevocationStore interface {
	Revoke(ctx context.Context, key string, expiresAt time.Time) error
	IsRevoked(ctx context.Context, key string) (bool, error)
}

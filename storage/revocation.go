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
// grant's ("grant:", the grant ID, "@" and the issuer), and a reused
// code's grant ("code-grant:", its ID, "@" and the issuer) share the
// store, and each must answer only for itself. Revoking a key again is not an error and leaves it revoked
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

// RevocationBatchChecker is an optional interface a revocation store
// (the server's Dependencies.Revocation, the resource server's
// resource.RevocationChecker) may implement to answer several IsRevoked
// questions in one round trip. The server and resource.Verifier each
// check a handful of keys per request — an access token's own key, its
// grant's key and its code grant's key, each also in the form a server
// before v0.61.0 wrote — and use IsAnyRevoked, when the store has it,
// instead of one IsRevoked call per key. A store without it gets exactly
// those IsRevoked calls.
//
// IsAnyRevoked reports whether any of keys has been revoked: the same
// answer as calling IsRevoked for each key and returning true on the
// first that is. An empty keys is false, nil. Keys are compared exactly,
// as IsRevoked compares them. An error means the answer isn't known, as
// for IsRevoked: the caller fails closed. Callers pass a few keys (at
// most five today); a store may refuse an unreasonably long keys with an
// error. TestRevocationStoreContract checks a store that implements it
// against IsRevoked.
//
// The server and resource.Verifier find IsAnyRevoked by type assertion,
// and then don't call IsRevoked at all. A wrapper that embeds a store
// implementing it inherits IsAnyRevoked through Go's method promotion,
// so a wrapper overriding IsRevoked (a cache tier, tenant prefixing, a
// fallback) is bypassed: the server asks the inner store, and a key the
// wrapper's IsRevoked reports revoked is accepted. A wrapper that
// overrides IsRevoked must also override IsAnyRevoked, or hold the
// inner store in a field of the plain RevocationStore (or
// resource.RevocationChecker) type, so nothing is promoted.
// TestRevocationStoreContract run against the wrapper catches the
// mismatch whenever IsAnyRevoked's answers disagree with the override's.
type RevocationBatchChecker interface {
	IsAnyRevoked(ctx context.Context, keys []string) (bool, error)
}

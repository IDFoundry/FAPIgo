package sqlstore

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/idfoundry/fapigo/storage"
)

// RevocationStore is a storage.RevocationStore: both
// server.Dependencies.Revocation (a server.RevocationSink) and a
// resource server's resource.RevocationChecker, one table shared
// between them.
type RevocationStore struct{ d *DB }

// Revocation returns d's storage.RevocationStore.
func (d *DB) Revocation() *RevocationStore { return &RevocationStore{d} }

// Revoke implements server.RevocationSink: one upsert, keeping the
// later of the key's expiries when it's revoked again.
func (s *RevocationStore) Revoke(ctx context.Context, key string, expiresAt time.Time) error {
	if !validTextKey(key) {
		return errors.New("sqlstore: revoke: key isn't valid UTF-8 without NUL")
	}
	until := nanos(expiresAt)
	err := s.d.writeOne(ctx, func(q querier) error {
		_, err := q.ExecContext(ctx, s.d.q("INSERT INTO {revocations} AS r (revocation_key, sweep_after) VALUES (?, ?) ON CONFLICT (revocation_key) DO UPDATE SET sweep_after = CASE WHEN excluded.sweep_after > r.sweep_after THEN excluded.sweep_after ELSE r.sweep_after END"),
			key, until)
		return err
	})
	if err != nil {
		return unavailable("revoke", err)
	}
	return nil
}

// IsRevoked implements resource.RevocationChecker: whether key, exactly
// (the comparison is case- and byte-exact), was revoked and hasn't been
// swept since its expiry.
func (s *RevocationStore) IsRevoked(ctx context.Context, key string) (bool, error) {
	if !validTextKey(key) {
		return false, nil // never revoked: Revoke refuses it
	}
	var n int
	if err := s.d.queryRow(ctx, "SELECT COUNT(*) FROM {revocations} WHERE revocation_key = ?", key).Scan(&n); err != nil {
		return false, unavailable("check revocation", err)
	}
	return n > 0, nil
}

// Batching returns s as a storage.RevocationStore that is also a
// storage.RevocationBatchChecker, for server.Dependencies.Revocation
// and resource.Dependencies.Revocation:
//
//	Revocation: db.Revocation().Batching(),
//
// Its IsAnyRevoked reports whether any of keys was revoked and hasn't
// been swept since its expiry, as IsRevoked would for each of them in
// turn — each compared exactly, and a key Revoke would refuse never
// revoked — in one SELECT EXISTS … WHERE revocation_key IN (…) for up
// to maxRevocationBatch keys at a time. No keys is false, nil. The
// server and a resource server discover it by type assertion, asking
// it once where they'd otherwise call IsRevoked once per key. It's
// otherwise s, a storage.StoreAssurance with s's Capabilities.
//
// It's a method returning an interface, rather than a method of s, so
// that only a deployment asking for it gets it: a wrapper of its own
// that embeds *RevocationStore and overrides IsRevoked (a cache in
// front of a shared store, say) would otherwise inherit IsAnyRevoked
// by promotion, and the server and resource server would ask that,
// past the override. A wrapper embedding what Batching returns, a
// storage.RevocationStore, isn't a RevocationBatchChecker unless it
// implements IsAnyRevoked itself.
func (s *RevocationStore) Batching() storage.RevocationStore { return batchingRevocationStore{s} }

// batchingRevocationStore is RevocationStore.Batching's store.
type batchingRevocationStore struct{ *RevocationStore }

// IsAnyRevoked implements storage.RevocationBatchChecker — see
// RevocationStore.Batching.
func (b batchingRevocationStore) IsAnyRevoked(ctx context.Context, keys []string) (bool, error) {
	return b.isAnyRevoked(ctx, keys)
}

// maxRevocationBatch is the most keys IsAnyRevoked asks about in one
// statement: callers pass a handful (a token's or grant's current and
// legacy key forms), and a longer list is asked about this many at a
// time, keeping the statement's placeholders well inside every
// dialect's limit and its prepared forms few.
const maxRevocationBatch = 16

// isAnyRevoked is batchingRevocationStore's IsAnyRevoked.
func (s *RevocationStore) isAnyRevoked(ctx context.Context, keys []string) (bool, error) {
	valid := make([]any, 0, len(keys))
	for _, key := range keys {
		if validTextKey(key) {
			valid = append(valid, key)
		}
	}
	for len(valid) > 0 {
		n := min(len(valid), maxRevocationBatch)
		if revoked, err := s.anyRevoked(ctx, valid[:n]); revoked || err != nil {
			return revoked, err
		}
		valid = valid[n:]
	}
	return false, nil
}

// anyRevoked is isAnyRevoked's statement for keys, 1 to
// maxRevocationBatch valid ones.
func (s *RevocationStore) anyRevoked(ctx context.Context, keys []any) (bool, error) {
	var revoked bool
	query := "SELECT EXISTS (SELECT 1 FROM {revocations} WHERE revocation_key IN (?" + strings.Repeat(", ?", len(keys)-1) + "))"
	if err := s.d.queryRow(ctx, query, keys...).Scan(&revoked); err != nil {
		return false, unavailable("check revocation", err)
	}
	return revoked, nil
}

// Capabilities implements storage.StoreAssurance — see the package
// documentation.
func (s *RevocationStore) Capabilities() storage.Capabilities { return s.d.capabilities() }

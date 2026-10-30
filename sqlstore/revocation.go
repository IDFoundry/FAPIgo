package sqlstore

import (
	"context"
	"errors"
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

// Capabilities implements storage.StoreAssurance — see the package
// documentation.
func (s *RevocationStore) Capabilities() storage.Capabilities { return s.d.capabilities() }

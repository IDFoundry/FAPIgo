package sqlstore

import (
	"context"
	"errors"
	"fmt"

	"github.com/idfoundry/fapigo/storage"
)

// ErrReplayed is what ReplayStore.UseOnce returns, wrapped, for a digest
// already recorded in its namespace.
var ErrReplayed = errors.New("sqlstore: replay detected")

// ReplayStore is a storage.ReplayStore: server.Dependencies.Replay, and
// a resource server's replay store too. It keeps only each digest, in
// its namespace, until its ExpiresAt.
type ReplayStore struct{ d *DB }

// Replay returns d's storage.ReplayStore.
func (d *DB) Replay() *ReplayStore { return &ReplayStore{d} }

// UseOnce implements storage.ReplayStore: one INSERT … ON CONFLICT DO
// NOTHING, which inserts the digest only if its namespace doesn't hold
// it already — of concurrent uses, exactly one inserts it. A digest
// stays recorded until Sweep removes it, after its ExpiresAt. The
// database's failure to answer wraps storage.ErrStoreUnavailable.
func (s *ReplayStore) UseOnce(ctx context.Context, use storage.ReplayUse) error {
	if !validTextKey(string(use.Namespace)) {
		return errors.New("sqlstore: use once: namespace isn't valid UTF-8 without NUL")
	}
	expires := nanos(use.ExpiresAt)
	var n int64
	err := s.d.writeOne(ctx, func(q querier) error {
		res, err := q.ExecContext(ctx, s.d.q("INSERT INTO {replay} (namespace, digest, sweep_after) VALUES (?, ?, ?) ON CONFLICT (namespace, digest) DO NOTHING"),
			string(use.Namespace), use.Digest[:], expires)
		if err != nil {
			return err
		}
		n, err = res.RowsAffected()
		return err
	})
	switch {
	case err != nil:
		return unavailable("use once", err)
	case n != 1:
		return fmt.Errorf("%w in namespace %q", ErrReplayed, use.Namespace)
	}
	return nil
}

// Capabilities implements storage.StoreAssurance — see the package
// documentation.
func (s *ReplayStore) Capabilities() storage.Capabilities { return s.d.capabilities() }

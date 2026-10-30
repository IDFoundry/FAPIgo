package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/idfoundry/fapigo/storage"
)

// NonceStore is a storage.NonceStore: server.Dependencies.Nonces, and a
// resource server's DPoP nonce store too.
type NonceStore struct{ d *DB }

// Nonces returns d's storage.NonceStore.
func (d *DB) Nonces() *NonceStore { return &NonceStore{d} }

// Issue implements storage.NonceStore. Issuing a nonce again sets its
// expiry to the new one.
func (s *NonceStore) Issue(ctx context.Context, issuance storage.NonceIssuance) error {
	if !validTextKey(issuance.Nonce) {
		return errors.New("sqlstore: issue DPoP nonce: nonce isn't valid UTF-8 without NUL")
	}
	expires := nanos(issuance.ExpiresAt)
	err := s.d.writeOne(ctx, func(q querier) error {
		_, err := q.ExecContext(ctx, s.d.q("INSERT INTO {dpop_nonces} (nonce, expires_at, sweep_after) VALUES (?, ?, ?) ON CONFLICT (nonce) DO UPDATE SET expires_at = excluded.expires_at, sweep_after = excluded.sweep_after"),
			issuance.Nonce, expires, expires)
		return err
	})
	if err != nil {
		return unavailable("issue DPoP nonce", err)
	}
	return nil
}

// Lookup implements storage.NonceStore. It leaves the nonce in place,
// and returns it even once expired, until Sweep removes it: the caller
// compares ExpiresAt.
func (s *NonceStore) Lookup(ctx context.Context, lookup storage.NonceLookup) (storage.NonceRecord, error) {
	if !validTextKey(lookup.Nonce) {
		return storage.NonceRecord{}, fmt.Errorf("sqlstore: look up DPoP nonce: %w", notFound("nonce"))
	}
	var expires int64
	err := s.d.db.QueryRowContext(ctx, s.d.q("SELECT expires_at FROM {dpop_nonces} WHERE nonce = ?"), lookup.Nonce).Scan(&expires)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return storage.NonceRecord{}, fmt.Errorf("sqlstore: look up DPoP nonce: %w", notFound("nonce"))
	case err != nil:
		return storage.NonceRecord{}, unavailable("look up DPoP nonce", err)
	}
	return storage.NonceRecord{ExpiresAt: timeOf(expires)}, nil
}

// Capabilities implements storage.StoreAssurance — see the package
// documentation.
func (s *NonceStore) Capabilities() storage.Capabilities { return s.d.capabilities() }

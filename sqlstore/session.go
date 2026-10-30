package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/idfoundry/fapigo/storage"
)

// SessionStore is a storage.SessionStore: a relying party's
// client.Dependencies.Sessions. It keeps each session's record, as the
// client hands it, under its state until Consume deletes it or Sweep
// removes it once expired.
type SessionStore struct{ d *DB }

// Sessions returns d's storage.SessionStore.
func (d *DB) Sessions() *SessionStore { return &SessionStore{d} }

// sessionsTable is the client sessions' table.
const sessionsTable = "client_sessions"

// errSessionUnknown is Consume's answer for a state it doesn't hold
// (unknown, consumed or swept).
var errSessionUnknown = fmt.Errorf("sqlstore: consume session: %w: state", ErrNotFound)

// Create implements storage.SessionStore. A state the store already
// holds is refused, as an outage: the client generates each one at
// random.
func (s *SessionStore) Create(ctx context.Context, session storage.NewSession) error {
	if !validTextKey(session.State) {
		return errors.New("sqlstore: create session: state isn't valid UTF-8 without NUL")
	}
	expires := nanos(session.ExpiresAt)
	err := s.d.writeOne(ctx, func(q querier) error {
		record, err := s.d.seal(blobRef{sessionsTable, recordColumn, session.State, ""}, session.Record)
		if err != nil {
			return err
		}
		_, err = q.ExecContext(ctx, s.d.q("INSERT INTO {client_sessions} (state, record, expires_at, sweep_after) VALUES (?, ?, ?, ?)"),
			session.State, record, expires, expires)
		return err
	})
	if err != nil {
		return unavailable("create session", err)
	}
	return nil
}

// Consume implements storage.SessionStore: in one transaction, a DELETE
// … RETURNING takes the session — of concurrent consumes, exactly one
// finds it — and its record is opened, so a Sealer's failure leaves the
// session in place rather than spent. It returns the session even once
// expired, until Sweep removes it: the client compares ExpiresAt.
func (s *SessionStore) Consume(ctx context.Context, consumption storage.SessionConsumption) (storage.ConsumedSession, error) {
	if !validTextKey(consumption.State) {
		return storage.ConsumedSession{}, errSessionUnknown
	}
	var out storage.ConsumedSession
	err := s.d.write(ctx, func(q querier) error {
		var stored []byte
		var expires int64
		if err := q.QueryRowContext(ctx, s.d.q("DELETE FROM {client_sessions} WHERE state = ? RETURNING record, expires_at"), consumption.State).
			Scan(&stored, &expires); err != nil {
			return err
		}
		record, err := s.d.open(blobRef{sessionsTable, recordColumn, consumption.State, ""}, stored)
		if err != nil {
			return err
		}
		out = storage.ConsumedSession{Record: record, ExpiresAt: timeOf(expires)}
		return nil
	})
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return storage.ConsumedSession{}, errSessionUnknown
	case err != nil:
		return storage.ConsumedSession{}, unavailable("consume session", err)
	}
	return out, nil
}

// Capabilities implements storage.StoreAssurance — see the package
// documentation.
func (s *SessionStore) Capabilities() storage.Capabilities { return s.d.sealedCapabilities() }

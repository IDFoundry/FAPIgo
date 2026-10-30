package sqlstore_test

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/sqlstore"
	"github.com/idfoundry/fapigo/storage"
)

// consumeSession is d's Consume of state.
func consumeSession(d *sqlstore.DB, state string) (storage.ConsumedSession, error) {
	return d.Sessions().Consume(context.Background(), storage.SessionConsumption{State: state})
}

// rawSession reads the record column of the session whose state is
// state.
func rawSession(t *testing.T, p *place, db *sql.DB, state string) []byte {
	t.Helper()
	var out []byte
	query := placeholders(p, "SELECT record FROM "+p.prefix+"client_sessions WHERE state = ?")
	if err := db.QueryRowContext(context.Background(), query, state).Scan(&out); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return out
}

// A state is a case-sensitive key, Consume returns a session even once
// it has expired (the client checks ExpiresAt), and a state the store
// already holds is refused rather than overwritten.
func TestSessionKeysAndExpiry(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		ctx := context.Background()
		d := freshDB(t, dialect)
		past := time.Now().Add(-time.Minute)
		must(t, d.Sessions().Create(ctx, storage.NewSession{State: "State", Record: secretGrant, ExpiresAt: past}))
		if err := d.Sessions().Create(ctx, storage.NewSession{State: "State", ExpiresAt: past}); err == nil {
			t.Fatal("Create(a state already held) = nil error, want a refusal")
		}
		if _, err := consumeSession(d, "state"); !errors.Is(err, sqlstore.ErrNotFound) {
			t.Fatalf("Consume(another case) = %v, want ErrNotFound", err)
		}
		got, err := consumeSession(d, "State")
		if err != nil || !bytes.Equal(got.Record, secretGrant) || !got.ExpiresAt.Equal(past) {
			t.Fatalf("Consume(an expired session) = %s, %v, %v, want the record and its expiry", got.Record, got.ExpiresAt, err)
		}
	})
}

// Of concurrent consumes of one state through several handles —
// separate pools, as separate processes have — exactly one wins.
func TestSessionConsumeIsAtomicAcrossHandles(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		p := newPlace(t, dialect)
		must(t, p.migrated().Sessions().Create(context.Background(), storage.NewSession{State: "s", ExpiresAt: time.Now().Add(time.Minute)}))
		var handles []*sqlstore.DB
		for range 4 {
			d, _ := p.openPool()
			handles = append(handles, d)
		}
		wins := concurrentWins(handles, func(d *sqlstore.DB, _ int) bool {
			_, err := consumeSession(d, "s")
			return err == nil
		})
		if wins != 1 {
			t.Fatalf("concurrent consumes across handles won %d times, want exactly 1", wins)
		}
	})
}

// A sealed session isn't in the database in the clear; its blob moved
// to another state is refused; and a Consume whose record doesn't open
// leaves the session in place, so a Sealer's outage doesn't spend it.
func TestSealedSessions(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		ctx := context.Background()
		sealer := testSealer(t)
		p := newPlace(t, dialect)
		d := p.migratedWith(sqlstore.Options{Sealer: sealer})
		_, db := p.open()
		later := time.Now().Add(time.Minute)
		must(t, d.Sessions().Create(ctx, storage.NewSession{State: "a", Record: secretGrant, ExpiresAt: later}))
		must(t, d.Sessions().Create(ctx, storage.NewSession{State: "b", Record: secretGrant, ExpiresAt: later}))
		stored := rawSession(t, p, db, "a")
		if len(stored) == 0 || stored[0] != 2 || bytes.Contains(stored, []byte("user-secret")) {
			t.Fatalf("stored session = %q, want it sealed, without the record in the clear", stored)
		}

		rawExec(t, p, db, "UPDATE "+p.prefix+"client_sessions SET record = ? WHERE state = 'b'", stored)
		_, err := consumeSession(d, "b")
		wantUnreadable(t, "Consume(a blob moved from another state)", err)

		_, err = consumeSession(p.migratedWith(sqlstore.Options{Sealer: failingSealer{}}), "a")
		if !errors.Is(err, storage.ErrStoreUnavailable) {
			t.Fatalf("Consume with a failing Sealer = %v, want storage.ErrStoreUnavailable", err)
		}
		if got, err := consumeSession(d, "a"); err != nil || !bytes.Equal(got.Record, secretGrant) {
			t.Fatalf("Consume after a failed one = %s, %v, want the session still there", got.Record, err)
		}
	})
}

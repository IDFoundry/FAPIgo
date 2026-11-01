package sqlstore_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/sqlstore"
	"github.com/idfoundry/fapigo/storage"
)

// serializablePlace is a PostgreSQL place, migrated, and a handle on it
// over a pool whose connections default to SERIALIZABLE isolation.
func serializablePlace(t *testing.T) (*place, *sqlstore.DB) {
	t.Helper()
	if postgresDSN == "" {
		t.Skip("PostgreSQL only: " + postgresDSNEnv + " is unset")
	}
	p := newPlace(t, sqlstore.Postgres)
	p.migrated()
	db, err := sql.Open("pgx", postgresDSN+"&default_transaction_isolation=serializable")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	var level string
	if err := db.QueryRowContext(context.Background(), "SHOW default_transaction_isolation").Scan(&level); err != nil || level != "serializable" {
		t.Fatalf("default_transaction_isolation = %q, %v, want serializable", level, err)
	}
	return p, p.handle(db)
}

// raceLockedRow runs change, a statement on the row a store call will
// wait on, in a transaction of its own; starts call; commits the
// transaction once call is waiting for the row's lock; and returns
// call's error.
func raceLockedRow(t *testing.T, change string, arg any, call func() error) error {
	t.Helper()
	ctx := context.Background()
	tx, err := postgresPool.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, change, arg); err != nil {
		t.Fatalf("%s: %v", change, err)
	}
	done := make(chan error, 1)
	go func() { done <- call() }()
	waitForLockWaiter(t)
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return <-done
}

// waitForLockWaiter waits until some session of the database waits on
// a lock.
func waitForLockWaiter(t *testing.T) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		var n int
		if err := postgresPool.QueryRow("SELECT COUNT(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND datname = current_database()").Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n > 0 {
			return
		}
	}
	t.Fatal("no session waited on the row's lock")
}

// On a database whose default isolation is SERIALIZABLE, a consume that
// loses a race to a concurrent one still gets its typed outcome — a
// reused code, a consumed session — rather than a serialization failure
// answered as an outage: the stores pin READ COMMITTED.
func TestPostgresWritesAreReadCommitted(t *testing.T) {
	ctx := context.Background()
	p, d := serializablePlace(t)
	hash := sha256.Sum256([]byte("isolation"))
	must(t, d.Grants().CreateAuthorizationCode(ctx, storage.NewAuthorizationCode{CodeHash: hash, ClientID: "c", Grant: secretGrant, ExpiresAt: time.Now().Add(time.Minute)}))
	err := raceLockedRow(t, "UPDATE "+p.prefix+"authorization_codes SET redeemed = 1 WHERE code_hash = $1", hash[:], func() error {
		_, err := d.Grants().RedeemAuthorizationCode(ctx, storage.AuthorizationCodeRedemption{CodeHash: hash, ClientID: "c"})
		return err
	})
	var reused *storage.AuthorizationCodeAlreadyRedeemedError
	if !errors.As(err, &reused) {
		t.Fatalf("RedeemAuthorizationCode losing a race = %v, want *AuthorizationCodeAlreadyRedeemedError", err)
	}

	must(t, d.Sessions().Create(ctx, storage.NewSession{State: "isolation", Record: secretGrant, ExpiresAt: time.Now().Add(time.Minute)}))
	err = raceLockedRow(t, "DELETE FROM "+p.prefix+"client_sessions WHERE state = $1", "isolation", func() error {
		_, err := d.Sessions().Consume(ctx, storage.SessionConsumption{State: "isolation"})
		return err
	})
	if !errors.Is(err, sqlstore.ErrNotFound) || errors.Is(err, storage.ErrStoreUnavailable) {
		t.Fatalf("Consume losing a race = %v, want ErrNotFound, not an outage", err)
	}
}

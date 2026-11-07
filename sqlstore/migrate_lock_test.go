package sqlstore_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/sqlstore"
)

// The migration lock is a function of the schema and the TablePrefix
// alone, and different for another prefix, another schema, or the two
// run together differently — and from the sweep lock and the
// prefix-only lock earlier releases took.
func TestMigrationLockKeyDependsOnSchemaAndPrefix(t *testing.T) {
	key := sqlstore.MigrationLockKeyOf("tenant_a", "fapigo_")
	if again := sqlstore.MigrationLockKeyOf("tenant_a", "fapigo_"); again != key {
		t.Fatalf("the same schema and prefix gave %d, then %d", key, again)
	}
	for _, other := range [][2]string{
		{"tenant_b", "fapigo_"},
		{"tenant_a", "oid4vc_"},
		{"public", "fapigo_"},
		{"tenant_afapigo_", ""},
		{"tenant_", "afapigo_"},
		{"", "fapigo_"},
	} {
		if sqlstore.MigrationLockKeyOf(other[0], other[1]) == key {
			t.Errorf("schema %q, prefix %q has tenant_a's fapigo_ key", other[0], other[1])
		}
	}
	if key == sqlstore.SweepLockKeyOf("tenant_a", "fapigo_") {
		t.Error("the migration lock is the sweep lock")
	}
	if key == sqlstore.LegacyMigrationLockKeyOf("fapigo_") {
		t.Error("the migration lock is the legacy, prefix-only one")
	}
}

// holdLock takes Postgres advisory lock key on a connection of
// postgresPool's own (shared, or exclusively), until the test ends.
func holdLock(t *testing.T, key int64, shared bool) {
	t.Helper()
	ctx := context.Background()
	conn, err := postgresPool.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	lock, unlock := "pg_advisory_lock", "pg_advisory_unlock"
	if shared {
		lock, unlock = lock+"_shared", unlock+"_shared"
	}
	if _, err := conn.ExecContext(ctx, "SELECT "+lock+"($1)", key); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = conn.ExecContext(context.Background(), "SELECT "+unlock+"($1)", key)
		_ = conn.Close()
	})
}

// migrateWaits reports whether d's Migrate waits on a lock rather than
// completing within a short deadline, failing the test on any other
// error.
func migrateWaits(t *testing.T, d *sqlstore.DB) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	err := d.Migrate(ctx)
	if err != nil && !errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
		t.Fatalf("Migrate: %v", err)
	}
	return err != nil
}

// On PostgreSQL, a Migrate of tables in one schema isn't held up by
// another's of tables with the same TablePrefix in another schema of
// the database, while one of the same schema's tables is; and a lock
// held as sqlstore v0.7.0's Migrate takes it, on the prefix alone,
// holds up a Migrate in either schema, so the two releases never
// migrate one set of tables at once during a rolling upgrade.
func TestPostgresMigrationLockIsPerSchema(t *testing.T) {
	if postgresDSN == "" {
		t.Skip("PostgreSQL only: " + postgresDSNEnv + " is unset")
	}
	other, otherPool := otherSchemaPool(t)
	ours := currentSchema(t, postgresPool)

	t.Run("exclusive", func(t *testing.T) {
		p := newPlace(t, sqlstore.Postgres)
		holdLock(t, sqlstore.MigrationLockKeyOf(ours, p.prefix), false)
		if migrateWaits(t, p.handle(otherPool)) {
			t.Fatal("the other schema's Migrate waited on this one's lock")
		}
		if currentSchema(t, otherPool) != other {
			t.Fatal("the other pool's schema isn't the other schema")
		}
		if !migrateWaits(t, p.handle(postgresPool)) {
			t.Fatal("this schema's Migrate didn't wait on its own lock")
		}
	})
	t.Run("concurrent", func(t *testing.T) {
		// One Migrate holds its schema's lock, mid-transaction, while the
		// other schema's runs to completion.
		p := newPlace(t, sqlstore.Postgres)
		ctx := context.Background()
		tx, err := postgresPool.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock_shared($1)", sqlstore.LegacyMigrationLockKeyOf(p.prefix)); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1)", sqlstore.MigrationLockKeyOf(ours, p.prefix)); err != nil {
			t.Fatal(err)
		}
		if migrateWaits(t, p.handle(otherPool)) {
			t.Fatal("the other schema's Migrate waited on a Migrate of this one's")
		}
	})
	t.Run("legacy", func(t *testing.T) {
		p := newPlace(t, sqlstore.Postgres)
		holdLock(t, sqlstore.LegacyMigrationLockKeyOf(p.prefix), false)
		if !migrateWaits(t, p.handle(postgresPool)) {
			t.Error("this schema's Migrate didn't wait on the legacy lock")
		}
		if !migrateWaits(t, p.handle(otherPool)) {
			t.Error("the other schema's Migrate didn't wait on the legacy lock")
		}
	})
	t.Run("legacy shared", func(t *testing.T) {
		// Holding the legacy lock shared, as another Migrate of this
		// release does, holds up neither.
		p := newPlace(t, sqlstore.Postgres)
		holdLock(t, sqlstore.LegacyMigrationLockKeyOf(p.prefix), true)
		for _, db := range []*sql.DB{postgresPool, otherPool} {
			if migrateWaits(t, p.handle(db)) {
				t.Fatal("Migrate waited on a shared hold of the legacy lock")
			}
		}
	})
}

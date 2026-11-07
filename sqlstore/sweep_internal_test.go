package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
)

// openSQLiteConn is a connection to a new SQLite file in WAL mode, on a
// pool closed when the test ends.
func openSQLiteConn(t *testing.T) (*sql.DB, *sql.Conn) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "db.sqlite")+"?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return db, conn
}

// withoutBusyWait runs fn with no busy timeout and sets the
// connection's own back; it reports a connection it can't use, and one
// whose timeout it can't set back, without running fn on the first.
func TestWithoutBusyWait(t *testing.T) {
	ctx := context.Background()
	_, conn := openSQLiteConn(t)
	var during int64
	if err := withoutBusyWait(ctx, conn, func() error {
		return conn.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&during)
	}); err != nil || during != 0 {
		t.Fatalf("busy_timeout during fn = %d, %v, want 0, nil", during, err)
	}
	var after int64
	if err := conn.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&after); err != nil || after != 10000 {
		t.Fatalf("busy_timeout after = %d, %v, want the DSN's 10000", after, err)
	}

	// fn's connection closed under it: the timeout can't be set back.
	if err := withoutBusyWait(ctx, conn, conn.Close); !errors.Is(err, sql.ErrConnDone) {
		t.Fatalf("withoutBusyWait on a connection closed by fn = %v, want sql.ErrConnDone", err)
	}
	ran := false
	if err := withoutBusyWait(ctx, conn, func() error { ran = true; return nil }); !errors.Is(err, sql.ErrConnDone) || ran {
		t.Fatalf("withoutBusyWait on a closed connection = %v (fn ran: %v), want sql.ErrConnDone, fn not run", err, ran)
	}
	if _, err := walCheckpoint(ctx, conn, "PASSIVE"); !errors.Is(err, sql.ErrConnDone) {
		t.Fatalf("walCheckpoint on a closed connection = %v, want sql.ErrConnDone", err)
	}
}

// A checkpoint that can't get a connection does nothing, and doesn't
// panic or block.
func TestCheckpointWithoutAConnection(t *testing.T) {
	db, _ := openSQLiteConn(t)
	d := &DB{db: db, dialect: SQLite}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d.checkpoint(ctx)
}

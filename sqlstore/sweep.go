package sqlstore

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"hash/fnv"
	"strconv"
	"time"
)

// sweptTables are the tables whose rows Sweep deletes once past their
// sweep_after.
var sweptTables = []string{
	"par_requests",                // NewPARRecord.ExpiresAt, or a later interaction's
	"interactions",                // BeginAuthorizationTransaction.HandleExpiresAt
	"authorization_codes",         // NewAuthorizationCode.ExpiresAt; once redeemed, + RedeemedCodeRetention, or a later issued token's
	"refresh_tokens",              // NewRefreshToken.ExpiresAt
	"replay",                      // ReplayUse.ExpiresAt
	"dpop_nonces",                 // NonceIssuance.ExpiresAt
	"revocations",                 // the latest expiresAt a key was revoked with
	"access_tokens",               // NewAccessToken.ExpiresAt
	"backchannel_authentications", // NewBackchannelAuthentication.ExpiresAt + BackchannelExpiredRetention
	sessionsTable,                 // NewSession.ExpiresAt
}

// Sweep deletes every row that expired before now, from every table
// that has them, and returns how many it deleted. The stores never
// delete an expired row themselves — the server refuses an expired
// record it reads — so run Sweep periodically (every few minutes, say)
// to keep the tables from growing without bound.
//
// A row is kept until everything that may still need it has expired: a
// pushed request until the last interaction begun from it, a redeemed
// authorization code until the tokens its redemption issued (so that
// reusing the code still revokes them, RFC 6749 §4.1.2) and at least
// RedeemedCodeRetention past its own expiry (so that it's still there
// when the server records those tokens), and a CIBA
// request until BackchannelExpiredRetention after it expires (so that a
// late poll is told it expired).
//
// Pass the server's own time (server.Dependencies.Clock, or a relying
// party's client.Dependencies.Clock for a DB holding only its
// sessions). Running Sweep late only keeps rows longer; passing a time
// ahead of the server's would forget replay digests and revocations the
// server still relies on.
//
// It deletes a bounded batch of rows per transaction (500 on SQLite,
// 10,000 on Postgres), so however many rows have expired, no
// transaction of its holds row locks, or SQLite's write lock, for long:
// the stores' own writes run between its batches. It stops between batches once ctx ends,
// returning ctx's error, wrapped, with the count of rows it deleted
// until then; each batch it ran stays deleted. On Postgres each batch
// first tries a transaction-level advisory lock keyed by d's
// TablePrefix and the schema its tables resolve to (on the
// connection's search_path), so instances sweeping the same tables at
// once don't run their batches together, while stores with the same
// prefix in other schemas of the database sweep independently. A
// Sweep that finds that lock held stops at once, without an error,
// returning the count of rows it deleted until then and leaving the
// tables it hadn't reached: the lock's holder is a Sweep on these same
// tables, of another instance (or another DB on them), in the middle
// of a batch, which goes on through the tables after it and deletes
// what had expired by the time it was passed. What expired after that
// time, or what it leaves if its own context ends, waits for the next
// Sweep — so (n, nil) doesn't say every expired row is gone, only that
// nothing failed. On SQLite, after a
// Sweep that deleted rows, it checkpoints the write-ahead log and, if
// that copied all of it back, truncates it (PRAGMA
// wal_checkpoint(PASSIVE), then TRUNCATE), so the space the deletes
// took in it is given back. The checkpoint is best effort and never
// waits: it runs outside d's write slot, on a connection whose busy
// timeout it sets to zero meanwhile, so while a connection — of any
// process — still reads an older snapshot, or writes, it gives up at
// once rather than holding up the writes behind it, leaves the rest to
// SQLite's next automatic checkpoint (or the next Sweep's), and isn't
// an error.
func (d *DB) Sweep(ctx context.Context, now time.Time) (int64, error) {
	var total int64
	for _, name := range sweptTables {
		n, err := d.sweepTable(ctx, name, nanos(now))
		total += n
		switch {
		case errors.Is(err, errSweepLocked):
			return total, nil
		case err != nil:
			return total, unavailable("sweep "+name, err)
		}
	}
	if d.dialect == SQLite && total > 0 {
		d.checkpoint(ctx)
	}
	return total, nil
}

// sweepBatchSize is how many rows each of Sweep's transactions deletes
// at most: on SQLite, whose deletes hold the database's one write lock,
// a few tens of milliseconds' worth. Each batch rewrites the index pages
// its rows' random keys are spread over, so smaller batches cost more
// in all, but the stores' writes between them wait less.
func (d *DB) sweepBatchSize() int64 {
	if d.dialect == SQLite {
		return 500
	}
	return 10000
}

// errSweepLocked is a Sweep batch's answer when another's holds the
// sweep lock.
var errSweepLocked = errors.New("sqlstore: sweep: another instance is sweeping")

// sweepTable deletes name's rows whose sweep_after is before now, a
// batch at a time, returning how many it deleted.
func (d *DB) sweepTable(ctx context.Context, name string, now int64) (int64, error) {
	query := "DELETE FROM {" + name + "} WHERE rowid IN (SELECT rowid FROM {" + name + "} WHERE sweep_after < ? LIMIT " + strconv.FormatInt(d.sweepBatchSize(), 10) + ")"
	args := []any{now}
	if d.dialect == Postgres {
		// A TID scan of the batch's rows; a row a concurrent
		// transaction changes meanwhile is re-checked, and kept if its
		// sweep_after has moved on.
		query = "DELETE FROM {" + name + "} WHERE ctid = ANY(ARRAY(SELECT ctid FROM {" + name + "} WHERE sweep_after < ? LIMIT " + strconv.FormatInt(d.sweepBatchSize(), 10) + ")) AND sweep_after < ?"
		args = append(args, now)
	}
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		n, err := d.sweepBatch(ctx, name, query, args)
		total += n
		if err != nil || n < d.sweepBatchSize() {
			return total, err
		}
	}
}

// sweepBatch runs query, one of sweepTable's deletes from table name,
// with args in a transaction of its own, returning how many rows it
// deleted. On Postgres it first takes the sweep lock for the schema
// name resolves to, or returns errSweepLocked.
func (d *DB) sweepBatch(ctx context.Context, name, query string, args []any) (int64, error) {
	var n int64
	err := d.write(ctx, func(q querier) error {
		if d.dialect == Postgres {
			schema, err := d.tableSchema(ctx, q, name)
			if err != nil {
				return err
			}
			var locked bool
			if err := q.QueryRowContext(ctx, "SELECT pg_try_advisory_xact_lock($1)", sweepLockKey(schema, d.prefix)).Scan(&locked); err != nil {
				return err
			}
			if !locked {
				return errSweepLocked
			}
		}
		res, err := q.ExecContext(ctx, d.q(query), args...)
		if err != nil {
			return err
		}
		n, err = res.RowsAffected()
		return err
	})
	return n, err
}

// tableSchema is the name of the Postgres schema that d's table name
// resolves to on q's connection, as the statements of d's that name it
// unqualified do: the first schema on the search_path holding it.
func (d *DB) tableSchema(ctx context.Context, q querier, name string) (string, error) {
	var schema string
	err := q.QueryRowContext(ctx, d.q("SELECT n.nspname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE c.oid = '{"+name+"}'::regclass")).Scan(&schema)
	return schema, err
}

// sweepLockKey is the Postgres advisory lock Sweep's batches take for
// the tables of TablePrefix prefix in schema: the same for every DB on
// those tables, on any instance, and distinct (but for a 64-bit hash's
// collisions) for another prefix or another schema, since advisory
// locks are shared by the whole database. A NUL, which neither a
// schema's name nor a prefix can hold, separates the two.
func sweepLockKey(schema, prefix string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte("fapigo sqlstore sweep\x00" + schema + "\x00" + prefix))
	return int64(h.Sum64()) //nolint:gosec // a lock key: wrapping around is fine
}

// checkpoint checkpoints a SQLite database's write-ahead log, and
// truncates it if that copied all of it back: best effort, and never
// waiting on another connection. A PASSIVE checkpoint takes no lock
// that writers wait for, and copies what no reader's snapshot still
// needs; only once it has copied everything does a TRUNCATE follow,
// which takes the write lock (as a write would) to reset the log, with
// almost nothing left to copy. Both run with a busy timeout of zero, so
// the TRUNCATE, finding a writer, or a reader that hasn't let go of the
// log, gives up at once rather than waiting the busy timeout while
// d's writes, and other processes', queue behind it. It runs outside
// sqliteWrites for the same reason: it never holds up a write of d's
// for longer than the reset itself. A checkpoint that gives up (its
// busy column is 1) isn't an error; SQLite's automatic checkpoints, or
// the next Sweep, take it further.
func (d *DB) checkpoint(ctx context.Context) {
	conn, err := d.db.Conn(ctx)
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	_ = withoutBusyWait(ctx, conn, func() error {
		complete, err := walCheckpoint(ctx, conn, "PASSIVE")
		if err != nil || !complete {
			return err
		}
		_, err = walCheckpoint(ctx, conn, "TRUNCATE")
		return err
	})
}

// walCheckpoint runs PRAGMA wal_checkpoint(mode) on conn, reporting
// whether it completed: not blocked (busy 0), with every frame of the
// log copied back to the database (log, -1 outside WAL mode, equal to
// checkpointed).
func walCheckpoint(ctx context.Context, conn *sql.Conn, mode string) (bool, error) {
	var busy, log, checkpointed int64
	if err := conn.QueryRowContext(ctx, "PRAGMA wal_checkpoint("+mode+")").Scan(&busy, &log, &checkpointed); err != nil { // NOSONAR: go:S2077 — mode is one of checkpoint's constants; PRAGMA takes no bound arguments.
		return false, err
	}
	return busy == 0 && log >= 0 && log == checkpointed, nil
}

// withoutBusyWait runs fn with conn's busy timeout set to zero, then
// sets it back to what it was. A connection whose timeout can't be set
// back is discarded, never handed back to the pool, where a write of
// d's would take it for one with d's busy timeout (busyConns) and fail
// at once rather than wait.
func withoutBusyWait(ctx context.Context, conn *sql.Conn, fn func() error) (err error) {
	var ms int64
	if err := conn.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&ms); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, "PRAGMA busy_timeout = 0"); err != nil {
		return err
	}
	defer func() {
		if _, rsErr := conn.ExecContext(context.WithoutCancel(ctx), "PRAGMA busy_timeout = "+strconv.FormatInt(ms, 10)); rsErr != nil { // NOSONAR: go:S2077 — the only value is the integer the connection reported; PRAGMA takes no bound arguments.
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
			err = errors.Join(err, rsErr)
		}
	}()
	return fn()
}

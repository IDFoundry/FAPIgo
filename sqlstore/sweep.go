package sqlstore

import (
	"context"
	"database/sql"
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
// first tries a transaction-level advisory lock of d's TablePrefix, so
// instances sweeping the same tables at once don't run their batches
// together: an instance that finds another's batch running stops at
// once, without an error, returning the count of rows it deleted until
// then — the other instance is deleting the rest. On SQLite, after a
// Sweep that deleted rows, it checkpoints the write-ahead log and
// truncates it (PRAGMA wal_checkpoint(TRUNCATE)), so the space the
// deletes took in it is given back; a checkpoint that can't complete,
// because a connection is still reading, is left to SQLite's next
// automatic one, and isn't an error.
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
		n, err := d.sweepBatch(ctx, query, args)
		total += n
		if err != nil || n < d.sweepBatchSize() {
			return total, err
		}
	}
}

// sweepBatch runs query, one of sweepTable's deletes, with args in a
// transaction of its own, returning how many rows it deleted. On
// Postgres it first takes the sweep lock, or returns errSweepLocked.
func (d *DB) sweepBatch(ctx context.Context, query string, args []any) (int64, error) {
	var n int64
	err := d.write(ctx, func(q querier) error {
		if d.dialect == Postgres {
			var locked bool
			if err := q.QueryRowContext(ctx, "SELECT pg_try_advisory_xact_lock($1)", d.sweepLockKey()).Scan(&locked); err != nil {
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

// sweepLockKey is the Postgres advisory lock Sweep's batches take for
// d's table prefix.
func (d *DB) sweepLockKey() int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte("fapigo sqlstore sweep " + d.prefix))
	return int64(h.Sum64()) //nolint:gosec // a lock key: wrapping around is fine
}

// checkpoint checkpoints a SQLite database's write-ahead log and
// truncates it, as a write would: holding sqliteWrites, on a connection
// with d's busy timeout. It's best effort: SQLite checkpoints
// automatically anyway, only without truncating the file.
func (d *DB) checkpoint(ctx context.Context) {
	_ = d.sqliteExclusive(ctx, func(conn *sql.Conn) error {
		_, err := conn.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)")
		return err
	})
}

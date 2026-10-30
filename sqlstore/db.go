package sqlstore

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/idfoundry/fapigo/storage"
)

// Dialect is the SQL database a DB talks to.
type Dialect int

const (
	_ Dialect = iota

	// Postgres is PostgreSQL, 13 or later, through any database/sql
	// driver (github.com/jackc/pgx/v5/stdlib, say). Each consume is one
	// statement, or a transaction whose UPDATE locks the row it checks.
	Postgres

	// SQLite is SQLite, 3.35 or later (for RETURNING), through any
	// database/sql driver (modernc.org/sqlite, say, which needs no cgo).
	// Every write runs in a transaction started with BEGIN IMMEDIATE,
	// taking the database's write lock up front. Open it with a busy
	// timeout and in WAL mode — see the package documentation.
	SQLite
)

// String names d.
func (d Dialect) String() string {
	switch d {
	case Postgres:
		return "postgres"
	case SQLite:
		return "sqlite"
	}
	return "Dialect(" + strconv.Itoa(int(d)) + ")"
}

// Options configures a DB.
type Options struct {
	// TablePrefix is put before every table name, so several DBs — or
	// another application's tables, OID4VCgo's sqlstore among them — can
	// share one database or schema: lower-case letters, digits and
	// underscores, starting with a letter, at most 32 characters. Empty
	// means "fapigo_".
	TablePrefix string

	// SQLiteBusyTimeout is how long a SQLite write waits for another
	// connection's write lock before failing. Zero means 10 seconds.
	// Ignored for Postgres.
	SQLiteBusyTimeout time.Duration

	// Sealer, if set, seals every record blob the stores write — the
	// server's pushed requests, interactions, authorization codes' and
	// refresh tokens' grants, opaque access tokens' records, and CIBA
	// requests and decisions — each bound to its table, column, row key,
	// client and TablePrefix, so a copy of the database reveals none of
	// them and a sealed blob can't be moved to another row. AESGCMSealer
	// is one, with a key kept outside the database. The columns the
	// stores look rows up, consume and sweep them by stay readable — see
	// the package documentation's Sealing section.
	//
	// With a Sealer, a store refuses a blob that isn't sealed (ErrRecordFormat),
	// unless ReadUnsealed is set; without one, it refuses a sealed blob.
	Sealer Sealer

	// ReadUnsealed lets a DB with a Sealer read blobs written before it
	// had one, while SealRecords seals them: set it only for that
	// migration, then clear it, since while it's set anyone who can write
	// to the database can plant a blob the Sealer never sealed. It
	// requires Sealer.
	ReadUnsealed bool
}

// DB holds FAPIgo's Authorization Server stores' tables in one SQL
// database. Make one with New, create its tables with Migrate, and take
// its stores from its methods, one per server.Dependencies field. It's
// safe for concurrent use.
type DB struct {
	db      *sql.DB
	dialect Dialect
	prefix  string
	busy    time.Duration

	// sqliteWrites serializes this DB's own SQLite write transactions,
	// which would otherwise only wait on SQLite's busy handler for each
	// other. Other processes, and other DBs on the same file, still do.
	sqliteWrites sync.Mutex

	queries sync.Map // query template → the dialect's query

	sealer       Sealer
	readUnsealed bool
}

const defaultTablePrefix = "fapigo_"

var tablePrefixPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

// New returns a DB using db, a database of dialect. It doesn't touch the
// database: run Migrate, from a deployment step or at startup, before
// using its stores, or CheckSchema where a deployment step migrates.
func New(db *sql.DB, dialect Dialect, opts Options) (*DB, error) {
	if db == nil {
		return nil, errors.New("sqlstore: nil *sql.DB")
	}
	if dialect != Postgres && dialect != SQLite {
		return nil, fmt.Errorf("sqlstore: unknown dialect %v", dialect)
	}
	prefix := opts.TablePrefix
	if prefix == "" {
		prefix = defaultTablePrefix
	}
	if !tablePrefixPattern.MatchString(prefix) {
		return nil, fmt.Errorf("sqlstore: table prefix %q must be lower-case letters, digits and underscores, starting with a letter, at most 32 characters", prefix)
	}
	busy := opts.SQLiteBusyTimeout
	if busy < 0 {
		return nil, errors.New("sqlstore: negative SQLiteBusyTimeout")
	}
	if busy == 0 {
		busy = 10 * time.Second
	}
	if opts.ReadUnsealed && opts.Sealer == nil {
		return nil, errors.New("sqlstore: ReadUnsealed without a Sealer")
	}
	return &DB{db: db, dialect: dialect, prefix: prefix, busy: busy, sealer: opts.Sealer, readUnsealed: opts.ReadUnsealed}, nil
}

// Dialect is the database's dialect.
func (d *DB) Dialect() Dialect { return d.dialect }

// capabilities is what every store of d declares. See the package
// documentation's Capabilities section for why each holds.
func (d *DB) capabilities() storage.Capabilities {
	if d.dialect == Postgres {
		return storage.Capabilities{Durable: true, AtomicConsume: true, CrossInstanceConsistent: true}
	}
	return storage.Capabilities{Durable: true, AtomicConsume: true, SerializableRedemption: true}
}

// sealedCapabilities is what a store whose records Options.Sealer seals
// declares: capabilities, and EncryptedAtRest with a Sealer — but not
// while ReadUnsealed lets rows written before it stay unsealed.
func (d *DB) sealedCapabilities() storage.Capabilities {
	c := d.capabilities()
	c.EncryptedAtRest = d.sealer != nil && !d.readUnsealed
	return c
}

// querier is what a store runs its statements on: the *sql.DB itself,
// or a transaction's *sql.Tx or *sql.Conn.
type querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// q turns template into the dialect's query: each {name} becomes the
// prefixed table name, and each ? a Postgres $n placeholder.
func (d *DB) q(template string) string {
	if v, ok := d.queries.Load(template); ok {
		return v.(string)
	}
	var b strings.Builder
	n := 0
	for i := 0; i < len(template); i++ {
		switch c := template[i]; {
		case c == '{':
			end := strings.IndexByte(template[i:], '}')
			b.WriteString(d.prefix)
			b.WriteString(template[i+1 : i+end])
			i += end
		case c == '?' && d.dialect == Postgres:
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
		default:
			b.WriteByte(c)
		}
	}
	query := b.String()
	d.queries.Store(template, query)
	return query
}

// queryRow runs template, one of this package's queries, on the
// database itself, outside any transaction.
func (d *DB) queryRow(ctx context.Context, template string, args ...any) *sql.Row {
	return d.db.QueryRowContext(ctx, d.q(template), args...) // NOSONAR: go:S2077 — template is a constant query of this package's; q substitutes only the validated TablePrefix and placeholders, and every value is a bound argument.
}

// write runs fn in a transaction, committing it if fn returns nil and
// rolling it back otherwise. On Postgres the rows fn's statements lock
// stay locked until then; on SQLite the transaction holds the
// database's write lock from its start.
func (d *DB) write(ctx context.Context, fn func(q querier) error) error {
	if d.dialect == SQLite {
		return d.sqliteWrite(ctx, fn)
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// writeOne runs fn, which makes one change in one statement: on the
// database itself for Postgres, where a statement is atomic, and as
// write does for SQLite, which then waits its busy timeout for the
// write lock.
func (d *DB) writeOne(ctx context.Context, fn func(q querier) error) error {
	if d.dialect == SQLite {
		return d.sqliteWrite(ctx, fn)
	}
	return fn(d.db)
}

// sqliteWrite is write for SQLite. database/sql's BeginTx can't ask for
// BEGIN IMMEDIATE, so this takes a connection and issues the
// transaction's statements itself.
func (d *DB) sqliteWrite(ctx context.Context, fn func(q querier) error) (err error) {
	d.sqliteWrites.Lock()
	defer d.sqliteWrites.Unlock()
	conn, err := d.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			// Never hand the pool a connection still in a transaction.
			if _, rbErr := conn.ExecContext(context.WithoutCancel(ctx), "ROLLBACK"); rbErr != nil && !noTransaction(rbErr) {
				_ = conn.Raw(func(any) error { return driver.ErrBadConn })
			}
		}
		_ = conn.Close()
	}()
	if _, err := conn.ExecContext(ctx, "PRAGMA busy_timeout = "+strconv.FormatInt(d.busy.Milliseconds(), 10)); err != nil { // NOSONAR: go:S2077 — the only value is an integer New validated; PRAGMA takes no bound arguments.
		return err
	}
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return err
	}
	if err := fn(conn); err != nil {
		return err
	}
	_, err = conn.ExecContext(ctx, "COMMIT")
	return err
}

// noTransaction reports whether err is SQLite's answer to a ROLLBACK
// with no transaction open: BEGIN failed, or COMMIT already ended it.
func noTransaction(err error) bool {
	return strings.Contains(err.Error(), "no transaction is active")
}

// ErrNotFound is what a store returns, wrapped, for a key it holds no
// record for (or, for a consume, no longer holds one for). It never
// wraps storage.ErrStoreUnavailable.
var ErrNotFound = errors.New("sqlstore: not found")

// notFound is ErrNotFound for what, an unknown key.
func notFound(what string) error {
	return fmt.Errorf("%w: %s", ErrNotFound, what)
}

// unavailable wraps err, the database's failure to answer op, with
// storage.ErrStoreUnavailable, so a caller answers it as an outage (500
// server_error) rather than as the client's fault: a replay store's
// error that doesn't wrap it means "replayed", and a client
// repository's means "unknown client". err stays wrapped too, so
// errors.Is still finds context.Canceled or context.DeadlineExceeded.
func unavailable(op string, err error) error {
	return fmt.Errorf("sqlstore: %s: %w: %w", op, storage.ErrStoreUnavailable, err)
}

// validTextKey reports whether key can be a text column's value on
// every dialect: PostgreSQL's text holds neither NUL nor invalid UTF-8.
// A key that can't is one no store holds, so a lookup answers it as
// unknown without asking the database (and failing, as an outage).
func validTextKey(key string) bool {
	return utf8.ValidString(key) && !strings.ContainsRune(key, 0)
}

// minNanos and maxNanos bound the times a BIGINT of Unix nanoseconds
// holds: about 1678 to 2262.
var (
	minNanos = time.Unix(0, math.MinInt64+1)
	maxNanos = time.Unix(0, math.MaxInt64)
)

// nanos is t as a BIGINT column: Unix nanoseconds, so an expiry the
// core compares round-trips exactly. The zero time (and anything before
// 1678) is math.MinInt64; anything after 2262 is clamped to the last
// representable instant.
func nanos(t time.Time) int64 {
	switch {
	case t.Before(minNanos):
		return math.MinInt64
	case t.After(maxNanos):
		return math.MaxInt64
	}
	return t.UnixNano()
}

// timeOf is nanos' inverse, in UTC.
func timeOf(n int64) time.Time {
	if n == math.MinInt64 {
		return time.Time{}
	}
	return time.Unix(0, n).UTC()
}

// blob is raw as a NOT NULL binary column's value: drivers write a nil
// []byte as NULL.
func blob(raw []byte) []byte {
	if raw == nil {
		return []byte{}
	}
	return raw
}

// rawJSON is a binary column read back as a record: nil when empty, as
// it was most likely written.
func rawJSON(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return b
}

// laterSweep is the SQL expression that keeps a row's sweep_after at
// least its ? argument — pass the same instant twice.
const laterSweep = "CASE WHEN sweep_after < ? THEN ? ELSE sweep_after END"

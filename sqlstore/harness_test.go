package sqlstore_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"

	"github.com/idfoundry/fapigo/sqlstore"
)

// postgresDSNEnv names the environment variable holding a PostgreSQL
// DSN (a postgres:// URL) the tests run against too. Without it they
// run against SQLite alone — except under CI (the CI environment
// variable set, as GitHub Actions sets it), where a missing DSN fails
// the run rather than silently skipping PostgreSQL.
const postgresDSNEnv = "FAPIGO_SQLSTORE_POSTGRES_DSN"

// postgresDSN is postgresDSNEnv's DSN, its search_path set to a schema
// of this test run's own (TestMain), or "".
var postgresDSN string

// postgresPool is the run's one pool of PostgreSQL connections: each
// storage is a table prefix of its own in the run's schema.
var postgresPool *sql.DB

func TestMain(m *testing.M) {
	os.Exit(runTests(m))
}

func runTests(m *testing.M) int {
	base := os.Getenv(postgresDSNEnv)
	if base == "" {
		if os.Getenv("CI") != "" {
			fmt.Fprintln(os.Stderr, postgresDSNEnv+" is unset under CI: the PostgreSQL tests must run there")
			return 1
		}
		return m.Run()
	}
	schema := "sqlstore_test_" + randomHex(6)
	admin, err := sql.Open("pgx", base)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open postgres:", err)
		return 1
	}
	defer func() { _ = admin.Close() }()
	ctx := context.Background()
	if _, err := admin.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
		fmt.Fprintln(os.Stderr, "create schema:", err)
		return 1
	}
	defer func() { _, _ = admin.ExecContext(ctx, "DROP SCHEMA "+schema+" CASCADE") }()
	u, err := url.Parse(base)
	if err != nil {
		fmt.Fprintln(os.Stderr, postgresDSNEnv+":", err)
		return 1
	}
	query := u.Query()
	query.Set("search_path", schema)
	u.RawQuery = query.Encode()
	postgresDSN = u.String()
	postgresPool, err = sql.Open("pgx", postgresDSN)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open postgres:", err)
		return 1
	}
	postgresPool.SetMaxOpenConns(16)
	defer func() { _ = postgresPool.Close() }()
	return m.Run()
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// dialects are the databases the tests run against: SQLite always,
// PostgreSQL with postgresDSNEnv set.
func dialects() []sqlstore.Dialect {
	if postgresDSN != "" {
		return []sqlstore.Dialect{sqlstore.SQLite, sqlstore.Postgres}
	}
	return []sqlstore.Dialect{sqlstore.SQLite}
}

// forEachDialect runs fn as a subtest for each dialect.
func forEachDialect(t *testing.T, fn func(t *testing.T, dialect sqlstore.Dialect)) {
	t.Helper()
	for _, dialect := range dialects() {
		t.Run(dialect.String(), func(t *testing.T) { fn(t, dialect) })
	}
}

// sqliteDSN is the DSN of a SQLite file at path, in WAL mode with a
// busy timeout, as the package documentation recommends. A file, not
// ":memory:": an in-memory database is private to each of the pool's
// connections unless opened in shared-cache mode, whose table locks
// fail with SQLITE_LOCKED instead of waiting the busy timeout, so it
// would test neither the concurrency nor the locking a deployment has.
func sqliteDSN(path string) string {
	return "file:" + path + "?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)"
}

// place is room for one set of empty tables — a SQLite file of its
// own, or a table prefix of its own in the run's PostgreSQL schema —
// and opens handles on it: each *sqlstore.DB on a *sql.DB of its own
// for SQLite, as another process would have.
type place struct {
	t       *testing.T
	dialect sqlstore.Dialect
	path    string // SQLite
	prefix  string
}

func newPlace(t *testing.T, dialect sqlstore.Dialect) *place {
	t.Helper()
	s := &place{t: t, dialect: dialect, prefix: "t" + randomHex(4) + "_"}
	if dialect == sqlstore.SQLite {
		s.path = filepath.Join(t.TempDir(), "store.db")
	}
	return s
}

// open returns an unmigrated handle on s: on a *sql.DB of its own for
// SQLite, and on the run's shared pool for PostgreSQL.
func (s *place) open() (*sqlstore.DB, *sql.DB) {
	s.t.Helper()
	if s.dialect == sqlstore.SQLite {
		return s.openPool()
	}
	return s.handle(postgresPool), postgresPool
}

// openPool returns an unmigrated handle on s, on a *sql.DB of its own
// (as another process would have), closed when the test ends.
func (s *place) openPool() (*sqlstore.DB, *sql.DB) {
	s.t.Helper()
	driver, dsn := "sqlite", sqliteDSN(s.path)
	if s.dialect == sqlstore.Postgres {
		driver, dsn = "pgx", postgresDSN
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		s.t.Fatalf("open %s: %v", s.dialect, err)
	}
	s.t.Cleanup(func() { _ = db.Close() })
	return s.handle(db), db
}

// handle is a handle on s over db.
func (s *place) handle(db *sql.DB) *sqlstore.DB {
	s.t.Helper()
	return s.handleWith(db, sqlstore.Options{})
}

// handleWith is a handle on s over db with opts, less their
// TablePrefix: s's.
func (s *place) handleWith(db *sql.DB, opts sqlstore.Options) *sqlstore.DB {
	s.t.Helper()
	opts.TablePrefix = s.prefix
	d, err := sqlstore.New(db, s.dialect, opts)
	if err != nil {
		s.t.Fatalf("sqlstore.New: %v", err)
	}
	return d
}

// migratedWith returns a migrated handle on s with opts, on the same
// *sql.DB as s's other handles for PostgreSQL and a new one for SQLite.
func (s *place) migratedWith(opts sqlstore.Options) *sqlstore.DB {
	s.t.Helper()
	_, db := s.open()
	d := s.handleWith(db, opts)
	if err := d.Migrate(context.Background()); err != nil {
		s.t.Fatalf("Migrate: %v", err)
	}
	return d
}

// migrated returns a migrated handle on s.
func (s *place) migrated() *sqlstore.DB {
	s.t.Helper()
	d, _ := s.open()
	if err := d.Migrate(context.Background()); err != nil {
		s.t.Fatalf("Migrate: %v", err)
	}
	return d
}

// freshDB is a migrated handle on fresh, empty tables.
func freshDB(t *testing.T, dialect sqlstore.Dialect) *sqlstore.DB {
	t.Helper()
	return newPlace(t, dialect).migrated()
}

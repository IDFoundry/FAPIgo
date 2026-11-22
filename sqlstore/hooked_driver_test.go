package sqlstore_test

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/idfoundry/fapigo/sqlstore"
)

// statementHook is called by a hooked connection (hookedDB) around each
// statement it runs: before it runs (after false) and once it has run
// (after true), with its text. A transaction it begins calls it with
// "BEGIN" before beginning and "COMMIT" before committing; SQLite's are
// statements of their own (BEGIN IMMEDIATE, COMMIT).
type statementHook func(query string, after bool)

// hookedDB is a *sql.DB on p's database whose connections call hook
// around every statement, so a test can pause a store's call at one of
// its statements and force an order of two calls' statements, without
// sleeps. level is a PostgreSQL connection's
// default_transaction_isolation: "" keeps the database's.
func hookedDB(t *testing.T, p *place, level string, hook statementHook) *sql.DB {
	t.Helper()
	name, dsn := "sqlite", sqliteDSN(p.path)
	if p.dialect == sqlstore.Postgres {
		name, dsn = "pgx", postgresDSN
		if level != "" {
			dsn += "&default_transaction_isolation=" + url.PathEscape(level)
		}
	}
	opened, err := sql.Open(name, dsn)
	must(t, err)
	drv := opened.Driver()
	must(t, opened.Close())
	var inner driver.Connector = dsnConnector{drv, dsn}
	if withConnector, ok := drv.(driver.DriverContext); ok {
		inner, err = withConnector.OpenConnector(dsn)
		must(t, err)
	}
	db := sql.OpenDB(hookedConnector{inner, hook})
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// dsnConnector opens a driver's connections by DSN, for a driver that
// has no Connector of its own.
type dsnConnector struct {
	drv driver.Driver
	dsn string
}

func (c dsnConnector) Connect(context.Context) (driver.Conn, error) { return c.drv.Open(c.dsn) }

func (c dsnConnector) Driver() driver.Driver { return c.drv }

// hookedConnector opens inner's connections, hooked.
type hookedConnector struct {
	inner driver.Connector
	hook  statementHook
}

func (c hookedConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.inner.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &hookedConn{Conn: conn, hook: c.hook}, nil
}

func (c hookedConnector) Driver() driver.Driver { return c.inner.Driver() }

// hookedConn is a driver's connection running its statements and
// transactions past hook. Both drivers the tests use implement the
// context methods it calls.
type hookedConn struct {
	driver.Conn
	hook statementHook
}

func (c *hookedConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	c.hook(query, false)
	defer c.hook(query, true)
	return c.Conn.(driver.ExecerContext).ExecContext(ctx, query, args)
}

func (c *hookedConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.hook(query, false)
	defer c.hook(query, true)
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, query, args)
}

func (c *hookedConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	c.hook("BEGIN", false)
	tx, err := c.Conn.(driver.ConnBeginTx).BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return hookedTx{tx, c.hook}, nil
}

func (c *hookedConn) CheckNamedValue(v *driver.NamedValue) error {
	if checker, ok := c.Conn.(driver.NamedValueChecker); ok {
		return checker.CheckNamedValue(v)
	}
	return driver.ErrSkip
}

func (c *hookedConn) ResetSession(ctx context.Context) error {
	if resetter, ok := c.Conn.(driver.SessionResetter); ok {
		return resetter.ResetSession(ctx)
	}
	return nil
}

// hookedTx is a transaction committing past hook.
type hookedTx struct {
	driver.Tx
	hook statementHook
}

func (t hookedTx) Commit() error {
	t.hook("COMMIT", false)
	return t.Tx.Commit()
}

// gate holds the call that reaches it until the test frees it.
type gate struct {
	reached, release chan struct{}
	once, freed      sync.Once
}

func newGate() *gate { return &gate{reached: make(chan struct{}), release: make(chan struct{})} }

// hold signals the gate reached and waits for it to be freed: the first
// time only.
func (g *gate) hold() {
	g.once.Do(func() {
		close(g.reached)
		<-g.release
	})
}

// free lets the call held at the gate, and any that reaches it later,
// go on. Freeing it again does nothing.
func (g *gate) free() { g.freed.Do(func() { close(g.release) }) }

// holdAfter is a hook holding at g once a statement match accepts has
// run, before the call goes on (and, in a transaction, commits).
func holdAfter(match func(string) bool, g *gate) statementHook {
	return func(query string, after bool) {
		if after && match(query) {
			g.hold()
		}
	}
}

// holdAtNextWrite is a hook holding at g once a statement match accepts
// has run and its transaction has ended, just before the call's next
// write begins: its next transaction, or its next statement.
func holdAtNextWrite(match func(string) bool, g *gate) statementHook {
	var ran atomic.Bool
	return func(query string, after bool) {
		switch {
		case after && match(query):
			ran.Store(true)
		case !after && ran.Load() && (strings.HasPrefix(query, "BEGIN") || strings.HasPrefix(query, "INSERT")):
			g.hold()
		}
	}
}

// holdBeforeCommitAfter is a hook holding at g before the commit of the
// transaction a statement match accepts ran in.
func holdBeforeCommitAfter(match func(string) bool, g *gate) statementHook {
	var ran atomic.Bool
	return func(query string, after bool) {
		switch {
		case after && match(query):
			ran.Store(true)
		case !after && ran.Load() && query == "COMMIT":
			g.hold()
		}
	}
}

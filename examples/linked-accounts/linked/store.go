package linked

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // database/sql's "sqlite" driver: pure Go, no cgo

	"github.com/idfoundry/fapigo/sqlstore"
)

// OpenDatabase opens the demo's SQLite database file at path, creating
// it if it doesn't exist: in WAL mode, so readers don't wait on
// writers, with a busy timeout, so a connection waits its turn for the
// write lock rather than failing (see sqlstore's package
// documentation).
func OpenDatabase(path string) (*sql.DB, error) {
	return sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)")
}

// stores are each party's sqlstore tables. They share one database
// file, as several services can share one database, each under a table
// prefix of its own; in a real deployment, the bank and the apps would
// each have a database of their own.
type stores struct {
	// bank holds Alder Bank's authorization server's stores: clients,
	// pushed requests, grants, refresh tokens, replay digests, DPoP
	// nonces and revocations. Its API reads the revocations too.
	bank *sqlstore.DB
	// api holds the API's own DPoP nonces, which must never be the
	// bank's (RFC 9449 keeps the two roles' nonces apart).
	api *sqlstore.DB
	// pocketwise and thriftly hold each app's sessions (client
	// Dependencies.Sessions).
	pocketwise, thriftly *sqlstore.DB
}

// newStores migrates each party's tables in db.
func newStores(ctx context.Context, db *sql.DB) (stores, error) {
	var s stores
	for _, p := range []struct {
		dst    **sqlstore.DB
		prefix string
	}{
		{&s.bank, "bank_"}, {&s.api, "bank_api_"}, {&s.pocketwise, "pocketwise_"}, {&s.thriftly, "thriftly_"},
	} {
		d, err := sqlstore.New(db, sqlstore.SQLite, sqlstore.Options{TablePrefix: p.prefix})
		if err != nil {
			return stores{}, err
		}
		// Nothing migrates implicitly: a real deployment runs Migrate from
		// a deployment step, or at startup as here.
		if err := d.Migrate(ctx); err != nil {
			return stores{}, fmt.Errorf("migrate %s tables: %w", p.prefix, err)
		}
		*p.dst = d
	}
	return s, nil
}

// Sweep deletes every row that expired before the demo clock's now,
// from every party's tables, and returns how many it deleted. The
// stores never delete an expired row themselves, so run it
// periodically.
func (w *World) Sweep(ctx context.Context) (int64, error) {
	var total int64
	for _, d := range []*sqlstore.DB{w.stores.bank, w.stores.api, w.stores.pocketwise, w.stores.thriftly} {
		n, err := d.Sweep(ctx, w.clock.Now())
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// SweepEvery runs Sweep every interval until ctx is done, logging what
// fails through logf.
func (w *World) SweepEvery(ctx context.Context, interval time.Duration, logf func(format string, args ...any)) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := w.Sweep(ctx); err != nil && ctx.Err() == nil {
				logf("sweep: %v", err)
			}
		}
	}
}

package sqlstore

import (
	"context"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/storage"
)

// SetClientCache bounds d's client cache to bound clients and sets its
// clock, before d is used.
func SetClientCache(d *DB, bound int, now func() time.Time) {
	d.clients.max = bound
	d.clients.now = now
}

// ClientCacheLen is how many clients d's client cache holds.
func ClientCacheLen(d *DB) int {
	d.clients.mu.Lock()
	defer d.clients.mu.Unlock()
	return len(d.clients.entries)
}

// ResolveClientCounting is ResolveClient, adding one to *parses each
// time it parses the row rather than reusing the cache's client.
func ResolveClientCounting(ctx context.Context, d *DB, id fapi.ClientID, parses *int) (storage.RegisteredClient, error) {
	return cachedRow(ctx, d.Clients(), "resolve client", id, parsedClient, func(config []byte) (storage.RegisteredClient, error) {
		*parses++
		return resolveRow(id, config)
	})
}

// LookupClientKeys is ClientKeys' lookup.
func LookupClientKeys(ctx context.Context, d *DB, id fapi.ClientID) (fapi.URL, []byte, error) {
	return d.Clients().lookupKeys(ctx, id)
}

// PinsIsolation reports whether d runs every Postgres write, single
// statements included, in a READ COMMITTED transaction.
func PinsIsolation(d *DB) bool { return d.pinIsolation.Load() }

// HoldSQLiteWrites takes d's SQLite write slot, as a write of d's own
// would, returning the function that releases it.
func HoldSQLiteWrites(d *DB) (release func()) {
	d.sqliteWrites <- struct{}{}
	return func() { <-d.sqliteWrites }
}

package sqlstore

import (
	"context"
	"crypto/sha256"
	"sync"
	"time"

	fapi "github.com/idfoundry/fapigo"
)

// defaultClientCacheSize is how many clients a DB's clientCache holds
// at most.
const defaultClientCacheSize = 4096

// parsedKind is which of a row's parsed forms a clientCacheEntry holds
// in each slot.
type parsedKind int

const (
	parsedClient parsedKind = iota // ResolveClient's storage.RegisteredClient
	parsedKeys                     // lookupKeys' ClientKeyRegistration
	parsedKinds
)

// clientCache is a DB's cache of its clients rows' parsed forms, so a
// row read back with the same configuration isn't parsed again: each
// entry is keyed by its client_id and the SHA-256 of the configuration
// it was parsed from, and only a successful parse is kept. Within ttl
// (Options.ClientCacheTTL) of the start of the read that last returned
// an entry's configuration, the row isn't read again for a parsed form
// the entry holds; one it doesn't hold (the configuration made keys but
// no client, say) is read again, so a parse error is never served from
// the cache. It holds at most max clients, dropping an arbitrary one to
// make room for another. The parsed forms it hands out are immutable
// (storage.RegisteredClient) or copied (a ClientKeyRegistration's
// JWKS), so no caller can change what another is handed. Put,
// PutWithKeys and Delete drop their client's entry and bump gen, so a
// read that began before one of them can't store what it read; and a
// read never replaces an entry for another configuration that a read
// begun after it returned, so a read that stalled can't bring back what
// a later one found replaced, by another DB, say, and give it a fresh
// ttl.
type clientCache struct {
	ttl time.Duration
	max int
	now func() time.Time

	mu      sync.Mutex
	gen     uint64
	entries map[fapi.ClientID]*clientCacheEntry
}

// clientCacheEntry is one client's row, as a clientCache holds it.
type clientCacheEntry struct {
	sum    [sha256.Size]byte // the configuration's
	read   time.Time         // when the latest read to return the configuration began
	parsed [parsedKinds]any  // by parsedKind; nil until parsed
}

// clock is c's time source.
func (c *clientCache) clock() time.Time {
	if c.now == nil {
		return time.Now()
	}
	return c.now()
}

// cacheRead is when a read of a client's row began: c's generation and
// c's clock, taken before the read's SELECT, to pass to lookup and
// store with what it returned.
type cacheRead struct {
	gen uint64
	at  time.Time
}

// begin is a cacheRead for a read about to begin.
func (c *clientCache) begin() cacheRead {
	c.mu.Lock()
	defer c.mu.Unlock()
	return cacheRead{gen: c.gen, at: c.clock()}
}

// fresh is id's parsed form of kind, if c holds it from a read less
// than c.ttl ago.
func (c *clientCache) fresh(id fapi.ClientID, kind parsedKind) (any, bool) {
	if c.ttl <= 0 {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.entries[id]
	if e == nil || e.parsed[kind] == nil || c.clock().Sub(e.read) >= c.ttl {
		return nil, false
	}
	return e.parsed[kind], true
}

// lookup is the parsed form of kind of id's configuration, summing to
// sum, if c holds it. Read r just returned that configuration, so the
// entry's ttl starts again from when r began, unless a later read's
// already did. (An entry c holds was stored by a read since the last
// write through this DB, so whether or not this read began before that
// write, the row read back the same since it.)
func (c *clientCache) lookup(id fapi.ClientID, sum [sha256.Size]byte, kind parsedKind, r cacheRead) (any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.entries[id]
	if e == nil || e.sum != sum || e.parsed[kind] == nil {
		return nil, false
	}
	if r.at.After(e.read) {
		e.read = r.at
	}
	return e.parsed[kind], true
}

// store records v, the parsed form of kind of id's configuration,
// summing to sum, which read r just returned, its ttl running from when
// r began. It stores nothing if a write through this DB since r began
// may have made it stale, or if c holds another configuration from a
// read that began after r: the row may have changed since r's SELECT.
func (c *clientCache) store(id fapi.ClientID, sum [sha256.Size]byte, kind parsedKind, v any, r cacheRead) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if r.gen != c.gen {
		return
	}
	e := c.entries[id]
	if e != nil && e.sum != sum && e.read.After(r.at) {
		return
	}
	if e == nil || e.sum != sum {
		e = c.add(id)
		e.sum = sum
	}
	if r.at.After(e.read) {
		e.read = r.at
	}
	e.parsed[kind] = v
}

// add puts a new, empty entry for id in c, dropping an arbitrary other
// client's if c is full. c.mu is held.
func (c *clientCache) add(id fapi.ClientID) *clientCacheEntry {
	if c.entries == nil {
		c.entries = make(map[fapi.ClientID]*clientCacheEntry)
	}
	limit := c.max
	if limit <= 0 {
		limit = defaultClientCacheSize
	}
	if _, ok := c.entries[id]; !ok && len(c.entries) >= limit {
		for other := range c.entries {
			delete(c.entries, other)
			break
		}
	}
	e := &clientCacheEntry{}
	c.entries[id] = e
	return e
}

// invalidate drops id's entry, after a write to its row.
func (c *clientCache) invalidate(id fapi.ClientID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gen++
	delete(c.entries, id)
}

// cachedRow is parse's result for client id's row, from r's clientCache
// when it holds it for the row's current configuration (or, within
// Options.ClientCacheTTL, for the configuration last read). A read
// error, and a parse error, are returned as they are, and never cached.
func cachedRow[T any](ctx context.Context, r *ClientRepository, op string, id fapi.ClientID, kind parsedKind, parse func(config []byte) (T, error)) (T, error) {
	c := &r.d.clients
	if v, ok := c.fresh(id, kind); ok {
		return v.(T), nil
	}
	read := c.begin()
	config, err := r.config(ctx, op, id)
	if err != nil {
		var zero T
		return zero, err
	}
	sum := sha256.Sum256(config)
	if v, ok := c.lookup(id, sum, kind, read); ok {
		return v.(T), nil
	}
	v, err := parse(config)
	if err != nil {
		var zero T
		return zero, err
	}
	c.store(id, sum, kind, v, read)
	return v, nil
}

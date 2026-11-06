package sqlstore_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/sqlstore"
	"github.com/idfoundry/fapigo/storage"
)

// fakeClock is a clock a test moves by hand.
type fakeClock struct{ now atomic.Int64 }

func newFakeClock() *fakeClock {
	c := &fakeClock{}
	c.now.Store(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano())
	return c
}

func (c *fakeClock) Now() time.Time          { return time.Unix(0, c.now.Load()) }
func (c *fakeClock) advance(d time.Duration) { c.now.Add(int64(d)) }

// cachePlace is a migrated place, a handle on it with opts and a fake
// clock, and a pool to write its clients table behind the handle's
// back, as another instance or the operator's SQL would.
type cachePlace struct {
	p     *place
	d     *sqlstore.DB
	raw   *sql.DB
	clock *fakeClock
}

func newCachePlace(t *testing.T, dialect sqlstore.Dialect, opts sqlstore.Options) *cachePlace {
	t.Helper()
	p := newPlace(t, dialect)
	d := p.migratedWith(opts)
	clock := newFakeClock()
	sqlstore.SetClientCache(d, 0, clock.Now)
	_, raw := p.open()
	return &cachePlace{p: p, d: d, raw: raw, clock: clock}
}

// exec runs stmt, with {clients} for the clients table and ? for each
// argument, on the raw pool.
func (c *cachePlace) exec(t *testing.T, stmt string, args ...any) {
	t.Helper()
	stmt = strings.ReplaceAll(stmt, "{clients}", c.p.prefix+"clients")
	if c.p.dialect == sqlstore.Postgres {
		for i := range args {
			stmt = strings.Replace(stmt, "?", fmt.Sprintf("$%d", i+1), 1)
		}
	}
	if _, err := c.raw.ExecContext(context.Background(), stmt, args...); err != nil {
		t.Fatal(err)
	}
}

// setConfig writes id's row as cfg, behind the handle's back.
func (c *cachePlace) setConfig(t *testing.T, cfg storage.RegisteredClientConfig) {
	t.Helper()
	doc, err := sqlstore.MarshalClientConfig(cfg)
	must(t, err)
	c.setRaw(t, cfg.ID, string(doc))
}

// setRaw writes id's row as doc, behind the handle's back.
func (c *cachePlace) setRaw(t *testing.T, id fapi.ClientID, doc string) {
	t.Helper()
	c.exec(t, "INSERT INTO {clients} (client_id, config) VALUES (?, ?) ON CONFLICT (client_id) DO UPDATE SET config = excluded.config", string(id), doc)
}

// scoped is client id's configuration, allowing scope.
func scoped(id fapi.ClientID, scope string) storage.RegisteredClientConfig {
	cfg := keyedClient(id)
	cfg.AllowedScopes = []string{scope}
	return cfg
}

// wantScope fails t unless d resolves client id allowing scope.
func wantScope(t *testing.T, d *sqlstore.DB, id fapi.ClientID, scope string) {
	t.Helper()
	c, err := d.Clients().ResolveClient(context.Background(), id)
	if err != nil || !c.AllowsScope(scope) {
		t.Fatalf("ResolveClient(%s) = %v, %v, want it allowing %q", id, c, err, scope)
	}
}

// wantResolveErr fails t unless d's ResolveClient(id) fails with an
// error wrapping each of want.
func wantResolveErr(t *testing.T, d *sqlstore.DB, id fapi.ClientID, want ...error) {
	t.Helper()
	_, err := d.Clients().ResolveClient(context.Background(), id)
	for _, w := range want {
		if !errors.Is(err, w) {
			t.Fatalf("ResolveClient(%s) = %v, want an error wrapping %v", id, err, w)
		}
	}
}

// Without a TTL, a row read back the same isn't parsed again, and one
// changed by anything — this DB's Put, or SQL behind its back — is
// parsed and served on the next request.
func TestClientCacheReusesParseUntilConfigChanges(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		ctx := context.Background()
		c := newCachePlace(t, dialect, sqlstore.Options{})
		must(t, c.d.Clients().Put(ctx, scoped("c", "a")))
		parses := 0
		resolve := func(wantScope string, wantParses int) {
			t.Helper()
			client, err := sqlstore.ResolveClientCounting(ctx, c.d, "c", &parses)
			if err != nil || !client.AllowsScope(wantScope) || parses != wantParses {
				t.Fatalf("ResolveClient = %v, %v after %d parses, want scope %q after %d", client, err, parses, wantScope, wantParses)
			}
		}
		resolve("a", 1)
		resolve("a", 1)
		resolve("a", 1)
		c.setConfig(t, scoped("c", "b")) // behind its back
		resolve("b", 2)
		resolve("b", 2)
		must(t, c.d.Clients().Put(ctx, scoped("c", "a")))
		resolve("a", 3)
		wantScope(t, c.d, "c", "a")
		c.exec(t, "DELETE FROM {clients} WHERE client_id = ?", "c")
		wantResolveErr(t, c.d, "c", sqlstore.ErrNotFound)
	})
}

// With a TTL, a client read less than the TTL ago is served as read,
// whatever the table now says, unless this DB wrote it; an unknown
// client isn't kept, so one added is served at once.
func TestClientCacheTTL(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		ctx := context.Background()
		const ttl = 5 * time.Second
		c := newCachePlace(t, dialect, sqlstore.Options{ClientCacheTTL: ttl})

		wantResolveErr(t, c.d, "c", sqlstore.ErrNotFound)
		c.setConfig(t, scoped("c", "a"))
		wantScope(t, c.d, "c", "a") // an unknown client wasn't kept

		c.setConfig(t, scoped("c", "b"))
		c.clock.advance(ttl - time.Millisecond)
		wantScope(t, c.d, "c", "a") // stale, within the TTL
		c.clock.advance(time.Millisecond)
		wantScope(t, c.d, "c", "b") // read again

		// The TTL runs from the last read, not the first.
		c.clock.advance(ttl - time.Millisecond)
		c.exec(t, "DELETE FROM {clients} WHERE client_id = ?", "c")
		wantScope(t, c.d, "c", "b")
		c.clock.advance(time.Millisecond)
		wantResolveErr(t, c.d, "c", sqlstore.ErrNotFound)

		// This DB's own writes take effect at once.
		must(t, c.d.Clients().Put(ctx, scoped("c", "a")))
		wantScope(t, c.d, "c", "a")
		must(t, c.d.Clients().Put(ctx, scoped("c", "b")))
		wantScope(t, c.d, "c", "b")
		if _, err := c.d.Clients().Delete(ctx, "c"); err != nil {
			t.Fatal(err)
		}
		wantResolveErr(t, c.d, "c", sqlstore.ErrNotFound)

		// Another DB's don't reach it before the TTL passes.
		other := c.p.migratedWith(sqlstore.Options{})
		must(t, other.Clients().Put(ctx, scoped("c", "a")))
		wantScope(t, c.d, "c", "a")
		must(t, other.Clients().Put(ctx, scoped("c", "b")))
		wantScope(t, c.d, "c", "a")
		c.clock.advance(ttl)
		wantScope(t, c.d, "c", "b")
	})
}

// With a TTL, ClientKeys serves the keys as read too, and this DB's
// PutWithKeys rekeys the client at once.
func TestClientCacheTTLKeys(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		ctx := context.Background()
		const ttl = 5 * time.Second
		c := newCachePlace(t, dialect, sqlstore.Options{ClientCacheTTL: ttl})
		source, err := c.d.ClientKeys(nil)
		must(t, err)
		must(t, c.d.Clients().PutWithKeys(ctx, keyedClient("c"), sqlstore.ClientKeyRegistration{JWKS: clientJWKS(t, "k1")}))
		wantKIDs(t, source, "c", "k1")

		doc, err := sqlstore.MarshalClientConfigWithKeys(keyedClient("c"), sqlstore.ClientKeyRegistration{JWKS: clientJWKS(t, "k2")})
		must(t, err)
		c.setRaw(t, "c", string(doc))
		wantKIDs(t, source, "c", "k1") // stale, within the TTL
		c.clock.advance(ttl)
		wantKIDs(t, source, "c", "k2")

		must(t, c.d.Clients().PutWithKeys(ctx, keyedClient("c"), sqlstore.ClientKeyRegistration{JWKS: clientJWKS(t, "k3")}))
		wantKIDs(t, source, "c", "k3")
	})
}

// The cache holds at most its bound of clients, and every client still
// resolves as its row says.
func TestClientCacheEvictionBound(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		for _, ttl := range []time.Duration{0, time.Hour} {
			t.Run(ttl.String(), func(t *testing.T) { testClientCacheEvictionBound(t, dialect, ttl) })
		}
	})
}

func testClientCacheEvictionBound(t *testing.T, dialect sqlstore.Dialect, ttl time.Duration) {
	ctx := context.Background()
	c := newCachePlace(t, dialect, sqlstore.Options{ClientCacheTTL: ttl})
	const bound = 3
	sqlstore.SetClientCache(c.d, bound, c.clock.Now)
	source, err := c.d.ClientKeys(nil)
	must(t, err)
	for i := range 10 {
		id := fapi.ClientID(fmt.Sprintf("c%d", i))
		must(t, c.d.Clients().PutWithKeys(ctx, scoped(id, string(id)), sqlstore.ClientKeyRegistration{JWKS: clientJWKS(t, string(id))}))
	}
	for range 3 {
		for i := range 10 {
			id := fapi.ClientID(fmt.Sprintf("c%d", i))
			wantScope(t, c.d, id, string(id))
			wantKIDs(t, source, id, string(id))
			if n := sqlstore.ClientCacheLen(c.d); n > bound {
				t.Fatalf("cache holds %d clients, want at most %d", n, bound)
			}
		}
	}
}

// A row that doesn't make a valid client fails as it does uncached,
// every time, with or without a TTL — an error is never kept — and a
// row valid for ClientKeys but not ResolveClient serves each as it
// would uncached.
func TestClientCacheErrorsUnchanged(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		for _, ttl := range []time.Duration{0, time.Hour} {
			t.Run(ttl.String(), func(t *testing.T) { testClientCacheErrorsUnchanged(t, dialect, ttl) })
		}
	})
}

func testClientCacheErrorsUnchanged(t *testing.T, dialect sqlstore.Dialect, ttl time.Duration) {
	c := newCachePlace(t, dialect, sqlstore.Options{ClientCacheTTL: ttl})
	source, err := c.d.ClientKeys(nil)
	must(t, err)
	outage := []error{storage.ErrStoreUnavailable, sqlstore.ErrClientConfig}

	c.setRaw(t, "c", `{"version":1,"redirect_uri":"https://rp.example/cb"}`) // unparsable
	for range 2 {
		wantResolveErr(t, c.d, "c", outage...)
		if _, err := resolveKIDs(source, "c"); !errors.Is(err, storage.ErrStoreUnavailable) || !errors.Is(err, sqlstore.ErrClientConfig) {
			t.Fatalf("keys of an unparsable row = %v, want ErrStoreUnavailable and ErrClientConfig", err)
		}
	}
	c.setRaw(t, "c", `{"version":1,"redirect_uris":["http://rp.example/cb"]}`) // NewRegisteredClient refuses it
	for range 2 {
		wantResolveErr(t, c.d, "c", outage...)
		wantKIDs(t, source, "c")
	}
	c.setConfig(t, scoped("c", "a")) // fixed: served at once, no error was kept
	wantScope(t, c.d, "c", "a")
	for range 2 {
		wantResolveErr(t, c.d, "missing", sqlstore.ErrNotFound)
	}
	wantResolveErr(t, c.d, "bad\x00id", sqlstore.ErrNotFound)

	// Once the TTL has passed, a row broken behind the cache's back
	// fails as it would uncached.
	c.setRaw(t, "c", `{"version":2}`)
	c.clock.advance(ttl)
	wantResolveErr(t, c.d, "c", outage...)
}

// What ResolveClient and ClientKeys return can't change what they
// return next: no caller can poison the cache.
func TestClientCacheValuesCantBeMutated(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		ctx := context.Background()
		c := newCachePlace(t, dialect, sqlstore.Options{ClientCacheTTL: time.Hour})
		cfg := keyedClient("c")
		cfg.ClientAuthMethods = []storage.ClientAuthMethod{storage.ClientAuthMethodPrivateKeyJWT}
		cfg.ClientAssertionAlgorithms = []fapi.SignatureAlgorithm{fapi.ES256}
		cfg.CertificateKeyThumbprints = []string{"thumb"}
		jwks := clientJWKS(t, "k1")
		must(t, c.d.Clients().PutWithKeys(ctx, cfg, sqlstore.ClientKeyRegistration{JWKS: jwks}))

		first, err := c.d.Clients().ResolveClient(ctx, "c")
		must(t, err)
		first.RedirectURIs()[0] = "https://evil.example/cb"
		first.ClientAuthMethods()[0] = storage.ClientAuthMethodTLSClientAuth
		first.ClientAssertionAlgorithms()[0] = fapi.PS256
		first.CertificateKeyThumbprints()[0] = "evil"
		again, err := c.d.Clients().ResolveClient(ctx, "c")
		must(t, err)
		if got := again.RedirectURIs(); len(got) != 1 || got[0] != "https://rp.example/cb" ||
			!again.AllowsClientAuthMethod(storage.ClientAuthMethodPrivateKeyJWT) ||
			!again.AllowsClientAssertionAlgorithm(fapi.ES256) ||
			again.CertificateKeyThumbprints()[0] != "thumb" {
			t.Fatalf("ResolveClient after mutating its last result = %v", again)
		}

		_, inline, err := sqlstore.LookupClientKeys(ctx, c.d, "c")
		must(t, err)
		for i := range inline {
			inline[i] = 'x'
		}
		_, inline, err = sqlstore.LookupClientKeys(ctx, c.d, "c")
		if err != nil || string(inline) != string(jwks) {
			t.Fatalf("keys after mutating the last result = %s, %v, want %s", inline, err, jwks)
		}
	})
}

// Concurrent lookups, and writes through this DB and behind its back,
// race neither the cache nor each other, and settle on the table's last
// write.
func TestClientCacheConcurrent(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		for _, ttl := range []time.Duration{0, time.Hour} {
			t.Run(ttl.String(), func(t *testing.T) { testClientCacheConcurrent(t, dialect, ttl) })
		}
	})
}

func testClientCacheConcurrent(t *testing.T, dialect sqlstore.Dialect, ttl time.Duration) {
	ctx := context.Background()
	c := newCachePlace(t, dialect, sqlstore.Options{ClientCacheTTL: ttl})
	sqlstore.SetClientCache(c.d, 2, c.clock.Now) // evictions too
	source, err := c.d.ClientKeys(nil)
	must(t, err)
	ids := []fapi.ClientID{"a", "b", "c"}
	for _, id := range ids {
		must(t, c.d.Clients().PutWithKeys(ctx, scoped(id, "s0"), sqlstore.ClientKeyRegistration{JWKS: clientJWKS(t, "k")}))
	}
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Go(func() {
			for i := range 20 {
				id := ids[(g+i)%len(ids)]
				if _, err := c.d.Clients().ResolveClient(ctx, id); err != nil {
					t.Error(err)
				}
				if _, err := resolveKIDs(source, id); err != nil {
					t.Error(err)
				}
				if g == 0 {
					if err := c.d.Clients().Put(ctx, scoped(id, fmt.Sprintf("s%d", i))); err != nil {
						t.Error(err)
					}
				}
			}
		})
	}
	wg.Wait()
	must(t, c.d.Clients().Put(ctx, scoped("a", "last")))
	wantScope(t, c.d, "a", "last")
}

func TestNewRefusesNegativeClientCacheTTL(t *testing.T) {
	db, err := sql.Open("sqlite", sqliteDSN(t.TempDir()+"/x.db"))
	must(t, err)
	defer func() { _ = db.Close() }()
	if _, err := sqlstore.New(db, sqlstore.SQLite, sqlstore.Options{ClientCacheTTL: -time.Second}); err == nil {
		t.Fatal("New with a negative ClientCacheTTL = nil error, want an error")
	}
}

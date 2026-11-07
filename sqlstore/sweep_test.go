package sqlstore_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/sqlstore"
	"github.com/idfoundry/fapigo/storage"
)

// sweepFixture is one of each kind of row, all expiring a minute after
// t0, except what something still live needs: the pushed request an
// interaction (expiring at five minutes) was begun from, the redeemed
// code whose access token expires at ten, and a key revoked until
// twenty.
type sweepFixture struct {
	d         *sqlstore.DB
	t0        time.Time
	usedCode  [32]byte
	replayUse storage.ReplayUse
}

func newSweepFixture(t *testing.T, dialect sqlstore.Dialect) sweepFixture {
	t.Helper()
	ctx := context.Background()
	f := sweepFixture{d: freshDB(t, dialect), t0: time.Now(), usedCode: sha256.Sum256([]byte("used"))}
	minute := f.t0.Add(time.Minute)
	f.replayUse = storage.ReplayUse{Namespace: "n", Digest: sha256.Sum256([]byte("jti")), ExpiresAt: minute}
	tx, g := f.d.Transactions(), f.d.Grants()
	must(t, tx.CreatePAR(ctx, storage.NewPARRecord{Reference: "begun", ClientID: "c", ExpiresAt: minute}))
	must(t, tx.CreatePAR(ctx, storage.NewPARRecord{Reference: "unbegun", ClientID: "c", ExpiresAt: minute}))
	_, err := tx.BeginAuthorization(ctx, storage.BeginAuthorizationTransaction{Reference: "begun", Handle: "h", HandleExpiresAt: f.t0.Add(5 * time.Minute), Now: f.t0})
	must(t, err)
	must(t, g.CreateAuthorizationCode(ctx, storage.NewAuthorizationCode{CodeHash: f.usedCode, ClientID: "c", ExpiresAt: minute}))
	_, err = g.RedeemAuthorizationCode(ctx, storage.AuthorizationCodeRedemption{CodeHash: f.usedCode})
	must(t, err)
	must(t, g.RecordIssuedAccessToken(ctx, f.usedCode, "at-1", f.t0.Add(10*time.Minute)))
	must(t, g.CreateAuthorizationCode(ctx, storage.NewAuthorizationCode{CodeHash: sha256.Sum256([]byte("unused")), ClientID: "c", ExpiresAt: minute}))
	must(t, g.CreateRefreshToken(ctx, storage.NewRefreshToken{TokenHash: sha256.Sum256([]byte("rt")), ClientID: "c", ExpiresAt: minute}))
	must(t, f.d.Replay().UseOnce(ctx, f.replayUse))
	must(t, f.d.Nonces().Issue(ctx, storage.NonceIssuance{Nonce: "nonce", ExpiresAt: minute}))
	must(t, f.d.Revocation().Revoke(ctx, "short", minute))
	must(t, f.d.Revocation().Revoke(ctx, "long", minute))
	must(t, f.d.Revocation().Revoke(ctx, "long", f.t0.Add(20*time.Minute)))
	must(t, f.d.AccessTokens().CreateAccessToken(ctx, storage.NewAccessToken{TokenHash: sha256.Sum256([]byte("at")), ClientID: "c", ExpiresAt: minute}))
	ciba := cibaRequest("swept", "poll")
	ciba.ExpiresAt = minute
	must(t, f.d.Backchannel().CreateBackchannelAuthentication(ctx, ciba))
	_, err = f.d.PairwiseSubjects().GetOrCreate(ctx, storage.PairwiseSubjectKey{Issuer: "i", Sector: "s", Subject: "u"}, "body")
	must(t, err)
	must(t, f.d.Sessions().Create(ctx, storage.NewSession{State: "expiring", ExpiresAt: minute}))
	must(t, f.d.Sessions().Create(ctx, storage.NewSession{State: "live", ExpiresAt: f.t0.Add(5 * time.Minute)}))
	return f
}

func must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestSweep(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		ctx := context.Background()
		f := newSweepFixture(t, dialect)
		if n, err := f.d.Sweep(ctx, f.t0); err != nil || n != 0 {
			t.Fatalf("Sweep before anything expired = %d, %v, want 0, nil", n, err)
		}
		// The unbegun request, the unused code, the refresh token, the
		// replay digest, the nonce, the short revocation, the access
		// token and the expiring session — not the CIBA request, kept
		// past its expiry.
		if n, err := f.d.Sweep(ctx, f.t0.Add(2*time.Minute)); err != nil || n != 8 {
			t.Fatalf("Sweep after a minute = %d, %v, want 8, nil", n, err)
		}
		checkSweptAfterAMinute(t, f)
		// The begun request, the long revocation, the digest recorded
		// again and the live session (the completed interaction is gone
		// already) — not the used code, kept RedeemedCodeRetention past
		// its expiry.
		if n, err := f.d.Sweep(ctx, f.t0.Add(30*time.Minute)); err != nil || n != 4 {
			t.Fatalf("Sweep after everything expired = %d, %v, want 4, nil", n, err)
		}
		checkSweptAfterEverything(t, f)
		checkCIBARetention(t, f)
	})
}

// checkCIBARetention checks that the CIBA request, which expired at a
// minute, still answers a poll as expired until
// BackchannelExpiredRetention after that, and Sweep removes it only
// then.
func checkCIBARetention(t *testing.T, f sweepFixture) {
	t.Helper()
	ctx := context.Background()
	retained := f.t0.Add(time.Minute + sqlstore.BackchannelExpiredRetention)
	if n, err := f.d.Sweep(ctx, retained.Add(-time.Second)); err != nil || n != 0 {
		t.Fatalf("Sweep just before the CIBA request's retention ends = %d, %v, want 0, nil", n, err)
	}
	var expired *storage.BackchannelAuthenticationExpiredError
	if err := pollAt(f.d.Backchannel(), cibaRequest("swept", "poll"), retained.Add(-time.Second)); !errors.As(err, &expired) {
		t.Fatalf("late poll within the retention = %v, want expired (expired_token)", err)
	}
	// With the used code, which expired at a minute too and is kept
	// RedeemedCodeRetention, also an hour, past that.
	if n, err := f.d.Sweep(ctx, retained.Add(time.Second)); err != nil || n != 2 {
		t.Fatalf("Sweep after the CIBA request's and the used code's retention = %d, %v, want 2, nil", n, err)
	}
	if err := pollAt(f.d.Backchannel(), cibaRequest("swept", "poll"), retained.Add(time.Second)); !errors.Is(err, sqlstore.ErrNotFound) {
		t.Fatalf("poll of a swept CIBA request = %v, want ErrNotFound", err)
	}
}

// checkSweptAfterEverything checks f once everything has expired and
// been swept: a revocation is forgotten, a pairwise subject never is.
func checkSweptAfterEverything(t *testing.T, f sweepFixture) {
	t.Helper()
	ctx := context.Background()
	if revoked, err := f.d.Revocation().IsRevoked(ctx, "long"); err != nil || revoked {
		t.Fatalf("IsRevoked(long) after its expiry's sweep = %v, %v, want false, nil", revoked, err)
	}
	if subject, err := f.d.PairwiseSubjects().Lookup(ctx, "i", "s", "body"); err != nil || subject != "u" {
		t.Fatalf("pairwise Lookup after every sweep = %q, %v, want u, nil", subject, err)
	}
}

// checkSweptAfterAMinute checks f once rows expiring at a minute are
// swept: what's still needed stays.
func checkSweptAfterAMinute(t *testing.T, f sweepFixture) {
	t.Helper()
	ctx := context.Background()
	if _, err := f.d.Transactions().CompleteAuthorization(ctx, storage.CompleteAuthorizationTransaction{Handle: "h"}); err != nil {
		t.Fatalf("CompleteAuthorization of a live interaction whose request expired = %v, want nil: its request must outlive the sweep", err)
	}
	var reused *storage.AuthorizationCodeAlreadyRedeemedError
	if _, err := f.d.Grants().RedeemAuthorizationCode(ctx, storage.AuthorizationCodeRedemption{CodeHash: f.usedCode}); !errors.As(err, &reused) || reused.IssuedAccessTokenKey != "at-1" {
		t.Fatalf("RedeemAuthorizationCode of a reused code whose access token is live = %v, want reuse reporting at-1", err)
	}
	if _, err := f.d.AccessTokens().LookupAccessToken(ctx, storage.AccessTokenLookup{TokenHash: sha256.Sum256([]byte("at"))}); !errors.Is(err, sqlstore.ErrNotFound) {
		t.Fatalf("LookupAccessToken of a swept token = %v, want ErrNotFound", err)
	}
	var expired *storage.BackchannelAuthenticationExpiredError
	if err := pollAt(f.d.Backchannel(), cibaRequest("swept", "poll"), f.t0.Add(2*time.Minute)); !errors.As(err, &expired) {
		t.Fatalf("poll of a CIBA request after its expiry, before its retention ends = %v, want expired (expired_token)", err)
	}
	if _, err := f.d.Nonces().Lookup(ctx, storage.NonceLookup{Nonce: "nonce"}); !errors.Is(err, sqlstore.ErrNotFound) {
		t.Fatalf("Lookup of a swept nonce = %v, want ErrNotFound", err)
	}
	if _, err := f.d.Sessions().Consume(ctx, storage.SessionConsumption{State: "expiring"}); !errors.Is(err, sqlstore.ErrNotFound) {
		t.Fatalf("Consume of a swept session = %v, want ErrNotFound", err)
	}
	if err := f.d.Replay().UseOnce(ctx, f.replayUse); err != nil {
		t.Fatalf("UseOnce of a swept digest = %v, want nil", err)
	}
	for key, want := range map[string]bool{"short": false, "long": true} {
		if revoked, err := f.d.Revocation().IsRevoked(ctx, key); err != nil || revoked != want {
			t.Fatalf("IsRevoked(%s) = %v, %v, want %v, nil", key, revoked, err, want)
		}
	}
}

// A code redeemed just before it expires outlives a Sweep run between
// its redemption and the server's RecordIssued* calls, so a reuse is
// still reported as one (and revokes what it issued), not as an unknown
// code; once RedeemedCodeRetention and its tokens have passed, it's
// swept.
func TestRedeemedCodeOutlivesSweepBeforeRecordIssued(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		ctx := context.Background()
		d := freshDB(t, dialect)
		g := d.Grants()
		t0 := time.Now()
		hash := sha256.Sum256([]byte("edge"))
		must(t, g.CreateAuthorizationCode(ctx, storage.NewAuthorizationCode{CodeHash: hash, ClientID: "c", Grant: secretGrant, ExpiresAt: t0.Add(time.Second)}))
		_, err := g.RedeemAuthorizationCode(ctx, storage.AuthorizationCodeRedemption{CodeHash: hash, ClientID: "c"})
		must(t, err)
		if n, err := d.Sweep(ctx, t0.Add(1001*time.Millisecond)); err != nil || n != 0 {
			t.Fatalf("Sweep just past the code's expiry = %d, %v, want 0, nil", n, err)
		}
		must(t, g.RecordIssuedAccessToken(ctx, hash, "jti-1", t0.Add(time.Minute)))
		_, err = g.RedeemAuthorizationCode(ctx, storage.AuthorizationCodeRedemption{CodeHash: hash, ClientID: "c"})
		var reused *storage.AuthorizationCodeAlreadyRedeemedError
		if !errors.As(err, &reused) || reused.IssuedAccessTokenKey != "jti-1" {
			t.Fatalf("reuse = %v, want *AuthorizationCodeAlreadyRedeemedError with the access token", err)
		}
		if n, err := d.Sweep(ctx, t0.Add(time.Second+sqlstore.RedeemedCodeRetention+time.Millisecond)); err != nil || n != 1 {
			t.Fatalf("Sweep after RedeemedCodeRetention = %d, %v, want 1, nil", n, err)
		}
	})
}

// A redeemed code whose expiry is the latest a BIGINT holds keeps it:
// RedeemedCodeRetention doesn't overflow.
func TestRedeemedCodeRetentionAtTheEndOfTime(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		ctx := context.Background()
		d := freshDB(t, dialect)
		hash := sha256.Sum256([]byte("forever"))
		must(t, d.Grants().CreateAuthorizationCode(ctx, storage.NewAuthorizationCode{CodeHash: hash, ClientID: "c", ExpiresAt: time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC)}))
		_, err := d.Grants().RedeemAuthorizationCode(ctx, storage.AuthorizationCodeRedemption{CodeHash: hash})
		must(t, err)
		if n, err := d.Sweep(ctx, time.Date(2262, 1, 1, 0, 0, 0, 0, time.UTC)); err != nil || n != 0 {
			t.Fatalf("Sweep = %d, %v, want 0, nil", n, err)
		}
	})
}

// insertExpiredReplay inserts n replay digests, past their sweep_after
// at sweepAfter, straight into p's table on db.
func insertExpiredReplay(t *testing.T, p *place, db *sql.DB, n int, sweepAfter int64) {
	t.Helper()
	query := "WITH RECURSIVE g(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM g WHERE x < ?) INSERT INTO " + p.prefix + "replay (namespace, digest, sweep_after) SELECT 'backlog', randomblob(32), ? FROM g"
	if p.dialect == sqlstore.Postgres {
		query = "INSERT INTO " + p.prefix + "replay (namespace, digest, sweep_after) SELECT 'backlog', sha256(int8send(g) || int8send($2)), $2 FROM generate_series(1, $1) g"
	}
	if _, err := db.ExecContext(context.Background(), query, n, sweepAfter); err != nil {
		t.Fatalf("insert %d expired replay rows: %v", n, err)
	}
}

// countRows is how many rows p's table holds, on db.
func countRows(t *testing.T, p *place, db *sql.DB, table string) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM "+p.prefix+table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Sweep deletes a backlog larger than its batches, all of it, and
// keeps what hasn't expired; on SQLite it leaves the write-ahead log
// truncated.
func TestSweepDeletesBacklogInBatches(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		ctx := context.Background()
		p := newPlace(t, dialect)
		d := p.migrated()
		_, db := p.open()
		backlog := 2*int(sqlstore.SweepBatchSize(d)) + 7
		now := time.Now()
		insertExpiredReplay(t, p, db, backlog, now.Add(-time.Minute).UnixNano())
		insertExpiredReplay(t, p, db, 3, now.Add(time.Minute).UnixNano())
		if n, err := d.Sweep(ctx, now); err != nil || n != int64(backlog) {
			t.Fatalf("Sweep = %d, %v, want %d, nil", n, err, backlog)
		}
		if n := countRows(t, p, db, "replay"); n != 3 {
			t.Fatalf("rows left after Sweep = %d, want the 3 live ones", n)
		}
		if dialect != sqlstore.SQLite {
			return
		}
		if info, err := os.Stat(p.path + "-wal"); err != nil || info.Size() != 0 {
			t.Fatalf("write-ahead log after Sweep: %v, %v, want it truncated", info, err)
		}
	})
}

// A Sweep whose context has ended deletes nothing more, and says so as
// an outage that still wraps the context's error.
func TestSweepStopsWithItsContext(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		p := newPlace(t, dialect)
		d := p.migrated()
		_, db := p.open()
		insertExpiredReplay(t, p, db, 10, 0)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		n, err := d.Sweep(ctx, time.Now())
		if n != 0 || !errors.Is(err, context.Canceled) || !errors.Is(err, storage.ErrStoreUnavailable) {
			t.Fatalf("Sweep with an ended context = %d, %v, want 0 and context.Canceled as an outage", n, err)
		}
		if left := countRows(t, p, db, "replay"); left != 10 {
			t.Fatalf("rows left = %d, want 10", left)
		}
	})
}

// On PostgreSQL, a Sweep that finds another instance's batch running —
// here, its lock held — stops without an error, deleting nothing, and
// sweeps once the lock is free.
func TestPostgresSweepSkipsWhileAnotherSweeps(t *testing.T) {
	if postgresDSN == "" {
		t.Skip("PostgreSQL only: " + postgresDSNEnv + " is unset")
	}
	ctx := context.Background()
	p := newPlace(t, sqlstore.Postgres)
	d := p.migrated()
	insertExpiredReplay(t, p, postgresPool, 10, 0)
	conn, err := postgresPool.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	key := sqlstore.SweepLockKey(d, currentSchema(t, postgresPool))
	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", key); err != nil {
		t.Fatal(err)
	}
	if n, err := d.Sweep(ctx, time.Now()); n != 0 || err != nil {
		t.Fatalf("Sweep while another holds the lock = %d, %v, want 0, nil", n, err)
	}
	if left := countRows(t, p, postgresPool, "replay"); left != 10 {
		t.Fatalf("rows left = %d, want 10", left)
	}
	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", key); err != nil {
		t.Fatal(err)
	}
	if n, err := d.Sweep(ctx, time.Now()); n != 10 || err != nil {
		t.Fatalf("Sweep once the lock is free = %d, %v, want 10, nil", n, err)
	}
}

// currentSchema is the schema db's connections create and find tables
// in.
func currentSchema(t *testing.T, db *sql.DB) string {
	t.Helper()
	var schema string
	if err := db.QueryRowContext(context.Background(), "SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	return schema
}

// The sweep lock is a function of the schema and the TablePrefix
// alone: the same for every DB on one schema's tables, and different
// for another prefix, another schema, or the two run together
// differently.
func TestSweepLockKeyDependsOnSchemaAndPrefix(t *testing.T) {
	key := sqlstore.SweepLockKeyOf("tenant_a", "fapigo_")
	if again := sqlstore.SweepLockKeyOf("tenant_a", "fapigo_"); again != key {
		t.Fatalf("the same schema and prefix gave %d, then %d", key, again)
	}
	pool, err := sql.Open("pgx", "postgres://unused.invalid/db") // never connected to
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pool.Close() }()
	d, err := sqlstore.New(pool, sqlstore.Postgres, sqlstore.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if sqlstore.SweepLockKey(d, "tenant_a") != key {
		t.Fatal("a DB's key isn't its default prefix's")
	}
	for _, other := range [][2]string{
		{"tenant_b", "fapigo_"},
		{"tenant_a", "oid4vc_"},
		{"public", "fapigo_"},
		{"tenant_afapigo_", ""},
		{"tenant_", "afapigo_"},
	} {
		if sqlstore.SweepLockKeyOf(other[0], other[1]) == key {
			t.Errorf("schema %q, prefix %q has tenant_a's fapigo_ key", other[0], other[1])
		}
	}
}

// On PostgreSQL, a Sweep of tables in one schema isn't held up by
// another's of tables with the same TablePrefix in another schema of
// the database: each takes a lock of its own, so one tenant's Sweep
// never silently skips another's tables.
func TestPostgresSweepLockIsPerSchema(t *testing.T) {
	if postgresDSN == "" {
		t.Skip("PostgreSQL only: " + postgresDSNEnv + " is unset")
	}
	ctx := context.Background()
	other := currentSchema(t, postgresPool) + "_other"
	if _, err := postgresPool.ExecContext(ctx, "CREATE SCHEMA "+other); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = postgresPool.ExecContext(context.Background(), "DROP SCHEMA "+other+" CASCADE") })
	u, err := url.Parse(postgresDSN)
	if err != nil {
		t.Fatal(err)
	}
	query := u.Query()
	query.Set("search_path", other)
	u.RawQuery = query.Encode()
	otherPool, err := sql.Open("pgx", u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = otherPool.Close() })

	p := newPlace(t, sqlstore.Postgres)
	d := p.migrated()
	theirs := p.handle(otherPool) // the same prefix, in the other schema
	must(t, theirs.Migrate(ctx))
	if got := currentSchema(t, otherPool); got != other {
		t.Fatalf("the other pool's schema is %q, want %q", got, other)
	}
	insertExpiredReplay(t, p, otherPool, 10, 0)

	conn, err := postgresPool.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	ours := sqlstore.SweepLockKey(d, currentSchema(t, postgresPool))
	if ours == sqlstore.SweepLockKey(theirs, other) {
		t.Fatal("the two schemas' tables share a sweep lock")
	}
	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", ours); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = conn.ExecContext(context.Background(), "SELECT pg_advisory_unlock($1)", ours) }()
	if n, err := theirs.Sweep(ctx, time.Now()); n != 10 || err != nil {
		t.Fatalf("the other schema's Sweep while this one's lock is held = %d, %v, want 10, nil", n, err)
	}
}

// On SQLite, a Sweep whose checkpoint can't complete — another
// connection, as another process's would be, holds a read snapshot from
// before its deletes — returns at once rather than waiting the busy
// timeout: a write of the same DB made alongside it isn't held up, nor
// is another process's, with a shorter busy timeout; the log is left
// for later, and the connection's busy timeout is set back. Once the
// reader lets go, the next Sweep truncates the log.
func TestSQLiteSweepCheckpointNeverWaits(t *testing.T) {
	ctx := context.Background()
	const busy = 3 * time.Second
	p := newPlace(t, sqlstore.SQLite)
	_, db := p.openPool()
	db.SetMaxOpenConns(1) // so the busy timeout read at the end is the checkpoint's connection's
	d := p.handleWith(db, sqlstore.Options{SQLiteBusyTimeout: busy})
	must(t, d.Migrate(ctx))
	insertExpiredReplay(t, p, db, 50, 0)

	_, other := p.openPool()
	reader, err := other.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Rollback() }()
	if n := 0; reader.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+p.prefix+"replay").Scan(&n) != nil || n != 50 {
		t.Fatalf("reader's snapshot: %d rows, want 50", n)
	}

	writeTook := make(chan time.Duration, 1)
	start := time.Now()
	go func() {
		s := time.Now()
		err := d.Replay().UseOnce(ctx, storage.ReplayUse{Namespace: "n", Digest: sha256.Sum256([]byte("alongside")), ExpiresAt: time.Now().Add(time.Hour)})
		if err != nil {
			t.Error(err)
		}
		writeTook <- time.Since(s)
	}()
	if n, err := d.Sweep(ctx, time.Now()); n != 50 || err != nil {
		t.Fatalf("Sweep = %d, %v, want 50, nil", n, err)
	}
	if took := time.Since(start); took > busy/3 {
		t.Fatalf("Sweep took %v with a reader on an older snapshot: its checkpoint waited", took)
	}
	if took := <-writeTook; took > busy/3 {
		t.Fatalf("a write alongside Sweep took %v", took)
	}
	_, shorter := p.openPool()
	d2 := p.handleWith(shorter, sqlstore.Options{SQLiteBusyTimeout: 200 * time.Millisecond})
	must(t, d2.Replay().UseOnce(ctx, storage.ReplayUse{Namespace: "n", Digest: sha256.Sum256([]byte("other process")), ExpiresAt: time.Now().Add(time.Hour)}))
	if info, err := os.Stat(p.path + "-wal"); err != nil || info.Size() == 0 {
		t.Fatalf("write-ahead log with a reader on an older snapshot: %v, %v, want it left as it was", info, err)
	}

	var ms int64
	if err := db.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&ms); err != nil || ms != busy.Milliseconds() {
		t.Fatalf("busy_timeout after Sweep's checkpoint = %d, %v, want %d: set back", ms, err, busy.Milliseconds())
	}

	must(t, reader.Rollback())
	insertExpiredReplay(t, p, db, 5, 0)
	if n, err := d.Sweep(ctx, time.Now()); n != 5 || err != nil {
		t.Fatalf("Sweep after the reader = %d, %v, want 5, nil", n, err)
	}
	if info, err := os.Stat(p.path + "-wal"); err != nil || info.Size() != 0 {
		t.Fatalf("write-ahead log after the reader let go: %v, %v, want it truncated", info, err)
	}
}

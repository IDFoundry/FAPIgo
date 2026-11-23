package sqlstore_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/sqlstore"
	"github.com/idfoundry/fapigo/storage"
)

// raceEnv is where one forced order of a refresh token's creation and
// revocation runs: a migrated place, a handle on it, and how to open a
// hooked one like it.
type raceEnv struct {
	t       *testing.T
	p       *place
	plain   *sqlstore.DB
	level   string // PostgreSQL's default_transaction_isolation for hooked handles: "" for the database's
	checked bool   // whether hooked handles run CheckSchema, and so pin READ COMMITTED where the default isn't
	hash    [32]byte
	key     string
}

func newRaceEnv(t *testing.T, dialect sqlstore.Dialect) raceEnv {
	t.Helper()
	p := newPlace(t, dialect)
	return raceEnv{t: t, p: p, plain: p.migrated(), hash: sha256.Sum256([]byte("raced token")), key: grantKey("raced")}
}

// newIsolationRaceEnv is newRaceEnv on PostgreSQL, every handle's
// connections defaulting to level, having run CheckSchema if checked.
func newIsolationRaceEnv(t *testing.T, level string, checked bool) raceEnv {
	t.Helper()
	p, d := isolationPlace(t, level, checked)
	return raceEnv{t: t, p: p, plain: d, level: level, checked: checked, hash: sha256.Sum256([]byte("raced token")), key: grantKey("raced")}
}

// hooked is a handle on e's tables whose statements run past hook.
func (e raceEnv) hooked(hook statementHook) *sqlstore.DB {
	e.t.Helper()
	d := e.p.handle(hookedDB(e.t, e.p, e.level, hook))
	if e.checked {
		must(e.t, d.CheckSchema(context.Background()))
	}
	return d
}

func (e raceEnv) create(d *sqlstore.DB) error {
	return d.Grants().CreateRefreshToken(context.Background(), storage.NewRefreshToken{
		TokenHash: e.hash, ClientID: "c", Grant: secretGrant, ExpiresAt: time.Now().Add(time.Hour), GrantKeys: []string{e.key},
	})
}

func (e raceEnv) revoke(d *sqlstore.DB) error {
	return d.Grants().RevokeRefreshToken(context.Background(), e.hash)
}

// isTokenInsert reports whether query is CreateRefreshToken's INSERT of
// a token's row in e's tables.
func (e raceEnv) isTokenInsert(query string) bool {
	return strings.HasPrefix(query, "INSERT INTO "+e.p.prefix+"refresh_tokens ") && !strings.Contains(query, "ON CONFLICT")
}

// isTombstoneWrite reports whether query is RevokeRefreshToken's upsert
// of a tombstone in e's tables.
func (e raceEnv) isTombstoneWrite(query string) bool {
	return strings.HasPrefix(query, "INSERT INTO "+e.p.prefix+"refresh_tokens ") && strings.Contains(query, "ON CONFLICT")
}

// isRevokeDelete reports whether query is RevokeRefreshToken's DELETE of
// a token in e's tables.
func (e raceEnv) isRevokeDelete(query string) bool {
	return strings.HasPrefix(query, "DELETE FROM "+e.p.prefix+"refresh_tokens WHERE token_hash = ")
}

// raceResult is what the two calls of a forced order returned: the one
// held at a gate, and the one run meanwhile.
type raceResult struct{ held, meanwhile error }

// whileHeld runs held until it reaches g, then meanwhile. When meanwhile
// waits for held, g is released once it does — on PostgreSQL, once
// meanwhile waits on held's row lock; on SQLite, whose writes are
// serialized, as soon as meanwhile has started, since it can't run
// before held's transaction ends — and otherwise once meanwhile has
// returned. A held call that returns without reaching g fails the test.
func (e raceEnv) whileHeld(g *gate, held, meanwhile func() error, waits bool) raceResult {
	e.t.Helper()
	defer g.free() // a test failing here mustn't leave held's transaction open
	heldErr, meanwhileErr := make(chan error, 1), make(chan error, 1)
	go func() { heldErr <- held() }()
	select {
	case <-g.reached:
	case err := <-heldErr:
		e.t.Fatalf("the held call returned %v without reaching the statement it's held at", err)
	}
	meanwhileDone := make(chan struct{})
	go func() {
		defer close(meanwhileDone)
		meanwhileErr <- meanwhile()
	}()
	var r raceResult
	switch {
	case !waits:
		r.meanwhile = <-meanwhileErr
		g.free()
		r.held = <-heldErr
		return r
	case e.p.dialect == sqlstore.Postgres:
		awaitLockWaiter(e.t, meanwhileDone)
	}
	g.free()
	r.held, r.meanwhile = <-heldErr, <-meanwhileErr
	return r
}

// awaitLockWaiter waits until some session of the database waits on a
// lock, or until done is closed: a call that never waited, as it should
// have, fails its race's checks rather than this wait.
func awaitLockWaiter(t *testing.T, done <-chan struct{}) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		select {
		case <-done:
			return
		default:
		}
		var n int
		must(t, postgresPool.QueryRow("SELECT COUNT(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND datname = current_database()").Scan(&n))
		if n > 0 {
			return
		}
	}
	t.Fatal("no session waited on a lock")
}

// tokenRow is what e's tables hold under e's hash: whether a row is
// there, whether it's a tombstone, and how many grant index rows it has.
func (e raceEnv) tokenRow() (stored, tombstone bool, indexed int) {
	e.t.Helper()
	_, db := e.p.open()
	var revoked int
	err := db.QueryRowContext(context.Background(), placeholders(e.p, "SELECT revoked FROM "+e.p.prefix+"refresh_tokens WHERE token_hash = ?"), e.hash[:]).Scan(&revoked)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		e.t.Fatal(err)
	}
	must(e.t, db.QueryRowContext(context.Background(), placeholders(e.p, "SELECT COUNT(*) FROM "+e.p.prefix+"refresh_token_grants WHERE token_hash = ?"), e.hash[:]).Scan(&indexed))
	return err == nil, revoked == 1, indexed
}

// checkTombstoneColumns checks that the row under e's hash holds a
// tombstone's columns, whether it was written as one or was a token
// stored under the hash that the tombstone's upsert turned into one: no
// client, the record the sealed format byte alone (03), and the earliest
// expiry there is. A release that doesn't know the revoked column, v0.9
// among them, reads those alone, so none of the token's may be left for
// it to redeem.
func (e raceEnv) checkTombstoneColumns() {
	e.t.Helper()
	_, db := e.p.open()
	var clientID string
	var record []byte
	var expires int64
	must(e.t, db.QueryRowContext(context.Background(), placeholders(e.p, "SELECT client_id, record, expires_at FROM "+e.p.prefix+"refresh_tokens WHERE token_hash = ?"), e.hash[:]).Scan(&clientID, &record, &expires))
	if clientID != "" || string(record) != "\x03" || expires != math.MinInt64 {
		e.t.Fatalf("tombstone = client_id %q, record %x, expires_at %d; want \"\", 03, %d", clientID, record, expires, int64(math.MinInt64))
	}
}

// check checks the outcome of a forced order: the token is never
// redeemable, a tombstone is left exactly when wantTombstone, holding
// none of the token's columns, and revoking its grant reports nothing,
// as the token was revoked already, and leaves the tombstone.
func (e raceEnv) check(wantTombstone bool) {
	e.t.Helper()
	if redeemable(e.t, e.plain.Grants(), e.hash) {
		e.t.Fatal("a refresh token RevokeRefreshToken returned nil for is redeemable")
	}
	if _, tombstone, _ := e.tokenRow(); tombstone != wantTombstone {
		e.t.Fatalf("tombstone left = %v, want %v", tombstone, wantTombstone)
	}
	if wantTombstone {
		e.checkTombstoneColumns()
	}
	if revoked := revokeGrantTokens(e.t, e.plain.Grants(), e.key); len(revoked) != 0 {
		e.t.Fatalf("revoking the token's grant reported %d tokens, want none", len(revoked))
	}
	if _, tombstone, _ := e.tokenRow(); tombstone != wantTombstone {
		e.t.Fatal("revoking the token's grant deleted its tombstone")
	}
}

// revocationRaces are the forced orders of a refresh token's creation
// (with a grant key, so a transaction of its own) and revocation.
// inTransaction says whether a revocation's tombstone is written in a
// transaction a test can hold before it commits: always on SQLite, and on
// PostgreSQL where the handle pins READ COMMITTED, not where it writes
// one statement on its own.
func revocationRaces(inTransaction bool) map[string]func(e raceEnv) {
	races := map[string]func(e raceEnv){
		"created before the revocation": raceCreateBeforeRevoke,
		"revoked before the creation":   raceRevokeBeforeCreate,
		"creation in flight":            raceCreateInFlight,
		"revocation in flight":          raceRevokeInFlight,
	}
	if inTransaction {
		races["tombstone written, uncommitted"] = raceTombstoneUncommitted
	}
	return races
}

// raceCreateBeforeRevoke: the token is stored, then revoked: deleted,
// leaving no tombstone.
func raceCreateBeforeRevoke(e raceEnv) {
	must(e.t, e.create(e.plain))
	must(e.t, e.revoke(e.plain))
	if stored, _, _ := e.tokenRow(); stored {
		e.t.Fatal("revoking a stored token left its row")
	}
	e.check(false)
}

// raceRevokeBeforeCreate: the revocation finds no token and writes a
// tombstone, so the token's later creation fails, storing no index row.
func raceRevokeBeforeCreate(e raceEnv) {
	must(e.t, e.revoke(e.plain))
	if err := e.create(e.plain); err == nil {
		e.t.Fatal("CreateRefreshToken after its hash was revoked = nil error, want a refusal")
	}
	if _, _, indexed := e.tokenRow(); indexed != 0 {
		e.t.Fatalf("a refused CreateRefreshToken left %d index rows", indexed)
	}
	e.check(true)
}

// raceCreateInFlight: the creation has inserted the token's row, not yet
// committed, when the revocation runs. On PostgreSQL the revocation's
// DELETE doesn't see the row, and its tombstone's upsert waits for the
// creation, then turns the row into the tombstone; on SQLite the
// revocation runs once the creation commits, and deletes the token.
func raceCreateInFlight(e raceEnv) {
	g := newGate()
	creator := e.hooked(holdAfter(e.isTokenInsert, g))
	r := e.whileHeld(g, func() error { return e.create(creator) }, func() error { return e.revoke(e.plain) }, true)
	must(e.t, r.held)
	must(e.t, r.meanwhile)
	e.check(e.p.dialect == sqlstore.Postgres)
}

// raceRevokeInFlight: the revocation's DELETE has found no token, and
// committed, when the creation runs and commits; the revocation's
// tombstone then turns the stored token into the tombstone.
func raceRevokeInFlight(e raceEnv) {
	g := newGate()
	revoker := e.hooked(holdAtNextWrite(e.isRevokeDelete, g))
	r := e.whileHeld(g, func() error { return e.revoke(revoker) }, func() error { return e.create(e.plain) }, false)
	must(e.t, r.held)
	must(e.t, r.meanwhile)
	if _, _, indexed := e.tokenRow(); indexed != 1 {
		e.t.Fatalf("the token stored meanwhile has %d index rows, want its 1", indexed)
	}
	e.check(true)
}

// raceTombstoneUncommitted: the revocation has written its tombstone,
// not yet committed, when the creation runs; the creation waits for it,
// then fails on it, storing no index row.
func raceTombstoneUncommitted(e raceEnv) {
	g := newGate()
	revoker := e.hooked(holdBeforeCommitAfter(e.isTombstoneWrite, g))
	r := e.whileHeld(g, func() error { return e.revoke(revoker) }, func() error { return e.create(e.plain) }, true)
	must(e.t, r.held)
	if r.meanwhile == nil {
		e.t.Fatal("CreateRefreshToken racing an uncommitted tombstone = nil error, want a refusal")
	}
	if _, _, indexed := e.tokenRow(); indexed != 0 {
		e.t.Fatalf("a refused CreateRefreshToken left %d index rows", indexed)
	}
	e.check(true)
}

// Once RevokeRefreshToken has returned nil, no refresh token under its
// hash is redeemable, whether CreateRefreshToken for it committed
// before, ran while the revocation did, or ran after, while the
// tombstone lasts: each order forced on each dialect.
func TestRevokedRefreshTokenIsNeverRedeemable(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		for name, race := range revocationRaces(dialect == sqlstore.SQLite) {
			t.Run(name, func(t *testing.T) { race(newRaceEnv(t, dialect)) })
		}
	})
}

// So it is on PostgreSQL whatever the connections' default isolation:
// at REPEATABLE READ and SERIALIZABLE a statement that loses a race is
// run again at READ COMMITTED, by a handle that writes one statement on
// its own, or from the start, by one that has read the default with
// CheckSchema (which, at READ COMMITTED, changes nothing).
func TestPostgresRevokedRefreshTokenIsNeverRedeemableAtEachIsolation(t *testing.T) {
	for _, handle := range []struct {
		level   string
		checked bool
	}{{"read committed", false}, {"repeatable read", false}, {"repeatable read", true}, {"serializable", false}, {"serializable", true}} {
		for name, race := range revocationRaces(handle.checked) {
			t.Run(fmt.Sprintf("%s/checked=%v/%s", handle.level, handle.checked, name), func(t *testing.T) {
				race(newIsolationRaceEnv(t, handle.level, handle.checked))
			})
		}
	}
}

// A tombstone lasts an hour: Sweep with the server's time keeps it
// until then, refusing a token stored under its hash, and removes it
// after.
func TestSweepRemovesTombstonesAfterAnHour(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		ctx := context.Background()
		e := newRaceEnv(t, dialect)
		must(t, e.revoke(e.plain))
		if n, err := e.plain.Sweep(ctx, time.Now().Add(59*time.Minute)); err != nil || n != 0 {
			t.Fatalf("Sweep within the hour = %d, %v, want 0, nil", n, err)
		}
		if err := e.create(e.plain); err == nil {
			t.Fatal("CreateRefreshToken within the tombstone's hour = nil error, want a refusal")
		}
		if n, err := e.plain.Sweep(ctx, time.Now().Add(61*time.Minute)); err != nil || n != 1 {
			t.Fatalf("Sweep after the hour = %d, %v, want the tombstone, nil", n, err)
		}
		if stored, _, _ := e.tokenRow(); stored {
			t.Fatal("Sweep after the hour left the tombstone")
		}
	})
}

// A tombstone is never opened as a sealed record: with a Sealer,
// redeeming its hash is an unknown token, not an unreadable record (an
// outage), and SealRecords leaves it as it is.
func TestTombstoneIsNoSealedRecord(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		ctx := context.Background()
		p := newPlace(t, dialect)
		d := p.migratedWith(sqlstore.Options{Sealer: testSealer(t)})
		hash := sha256.Sum256([]byte("revoked before it was stored"))
		must(t, d.Grants().RevokeRefreshToken(ctx, hash))
		if _, err := d.Grants().RedeemRefreshToken(ctx, storage.RefreshTokenRedemption{TokenHash: hash}); !errors.Is(err, sqlstore.ErrNotFound) || errors.Is(err, storage.ErrStoreUnavailable) {
			t.Fatalf("RedeemRefreshToken(a tombstone, sealed DB) = %v, want ErrNotFound", err)
		}
		if n, err := d.SealRecords(ctx); err != nil || n != 0 {
			t.Fatalf("SealRecords with a tombstone alone = %d, %v, want 0, nil", n, err)
		}
		_, db := p.open()
		if stored := rawColumn(t, p, db, "refresh_tokens", "record", ""); string(stored) != "\x03" {
			t.Fatalf("a tombstone's record = %x, want the one format byte 03", stored)
		}
	})
}

// Revoking a hash again keeps its tombstone a tombstone, one row.
func TestRevokingATombstoneAgainKeepsIt(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		e := newRaceEnv(t, dialect)
		must(t, e.revoke(e.plain))
		must(t, e.revoke(e.plain))
		_, db := e.p.open()
		if n := countRows(t, e.p, db, "refresh_tokens"); n != 1 {
			t.Fatalf("revoking a hash twice = %d rows, want one tombstone", n)
		}
		e.check(true)
	})
}

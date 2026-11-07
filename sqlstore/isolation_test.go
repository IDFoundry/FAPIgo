package sqlstore_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/sqlstore"
	"github.com/idfoundry/fapigo/storage"
)

// serializablePlace is a PostgreSQL place, migrated, and a handle on it
// over a pool whose connections default to SERIALIZABLE isolation, on
// which neither Migrate nor CheckSchema has run.
func serializablePlace(t *testing.T) (*place, *sqlstore.DB) {
	t.Helper()
	return isolationPlace(t, "serializable", false)
}

// isolationPlace is a PostgreSQL place, migrated, and a handle on it
// over a pool whose connections default to level; with checked, the
// handle has run CheckSchema, and so read that default.
func isolationPlace(t *testing.T, level string, checked bool) (*place, *sqlstore.DB) {
	t.Helper()
	if postgresDSN == "" {
		t.Skip("PostgreSQL only: " + postgresDSNEnv + " is unset")
	}
	p := newPlace(t, sqlstore.Postgres)
	p.migrated()
	db, err := sql.Open("pgx", postgresDSN+"&default_transaction_isolation="+url.PathEscape(level))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	var got string
	if err := db.QueryRowContext(context.Background(), "SHOW default_transaction_isolation").Scan(&got); err != nil || got != level {
		t.Fatalf("default_transaction_isolation = %q, %v, want %q", got, err, level)
	}
	d := p.handle(db)
	if checked {
		must(t, d.CheckSchema(context.Background()))
	}
	if sqlstore.PinsIsolation(d) != checked {
		t.Fatalf("PinsIsolation = %v, want %v", sqlstore.PinsIsolation(d), checked)
	}
	return p, d
}

// raceLockedRow runs change, a statement on the row a store call will
// wait on, in a transaction of its own; starts call; commits the
// transaction once call is waiting for the row's lock; and returns
// call's error.
func raceLockedRow(t *testing.T, change string, arg any, call func() error) error {
	t.Helper()
	ctx := context.Background()
	tx, err := postgresPool.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, change, arg); err != nil {
		t.Fatalf("%s: %v", change, err)
	}
	done := make(chan error, 1)
	go func() { done <- call() }()
	waitForLockWaiter(t)
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return <-done
}

// waitForLockWaiter waits until some session of the database waits on
// a lock.
func waitForLockWaiter(t *testing.T) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		var n int
		if err := postgresPool.QueryRow("SELECT COUNT(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND datname = current_database()").Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n > 0 {
			return
		}
	}
	t.Fatal("no session waited on the row's lock")
}

// On a database whose default isolation is SERIALIZABLE, a consume that
// loses a race to a concurrent one still gets its typed outcome — a
// reused code, a consumed session — rather than a serialization failure
// answered as an outage: the stores pin READ COMMITTED.
func TestPostgresWritesAreReadCommitted(t *testing.T) {
	ctx := context.Background()
	p, d := serializablePlace(t)
	hash := sha256.Sum256([]byte("isolation"))
	must(t, d.Grants().CreateAuthorizationCode(ctx, storage.NewAuthorizationCode{CodeHash: hash, ClientID: "c", Grant: secretGrant, ExpiresAt: time.Now().Add(time.Minute)}))
	err := raceLockedRow(t, "UPDATE "+p.prefix+"authorization_codes SET redeemed = 1 WHERE code_hash = $1", hash[:], func() error {
		_, err := d.Grants().RedeemAuthorizationCode(ctx, storage.AuthorizationCodeRedemption{CodeHash: hash, ClientID: "c"})
		return err
	})
	var reused *storage.AuthorizationCodeAlreadyRedeemedError
	if !errors.As(err, &reused) {
		t.Fatalf("RedeemAuthorizationCode losing a race = %v, want *AuthorizationCodeAlreadyRedeemedError", err)
	}

	must(t, d.Sessions().Create(ctx, storage.NewSession{State: "isolation", Record: secretGrant, ExpiresAt: time.Now().Add(time.Minute)}))
	err = raceLockedRow(t, "DELETE FROM "+p.prefix+"client_sessions WHERE state = $1", "isolation", func() error {
		_, err := d.Sessions().Consume(ctx, storage.SessionConsumption{State: "isolation"})
		return err
	})
	if !errors.Is(err, sqlstore.ErrNotFound) || errors.Is(err, storage.ErrStoreUnavailable) {
		t.Fatalf("Consume losing a race = %v, want ErrNotFound, not an outage", err)
	}
}

// singleStatementRace is a single-statement write losing a race: change
// (with arg) commits a change to the row call's statement waits on, and
// check judges call's outcome.
type singleStatementRace struct {
	name   string
	setup  func(t *testing.T, d *sqlstore.DB)
	change string // with {p} for the table prefix
	arg    any
	call   func(d *sqlstore.DB) error
	check  func(t *testing.T, err error)
}

// singleStatementRaces are a race for each kind of single-statement
// write: a conditional UPDATE, an UPDATE, a DELETE, INSERT … ON
// CONFLICT DO NOTHING, and an upsert.
func singleStatementRaces() []singleStatementRace {
	ctx := context.Background()
	code := sha256.Sum256([]byte("race code"))
	token := sha256.Sum256([]byte("race token"))
	digest := sha256.Sum256([]byte("race jti"))
	createCode := func(t *testing.T, d *sqlstore.DB) {
		t.Helper()
		must(t, d.Grants().CreateAuthorizationCode(ctx, storage.NewAuthorizationCode{CodeHash: code, ClientID: "c", Grant: secretGrant, ExpiresAt: time.Now().Add(time.Minute)}))
	}
	wantNil := func(t *testing.T, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("losing a race = %v, want nil", err)
		}
	}
	return []singleStatementRace{{
		name: "redeem code", setup: createCode,
		change: "UPDATE {p}authorization_codes SET redeemed = 1 WHERE code_hash = $1", arg: code[:],
		call: func(d *sqlstore.DB) error {
			_, err := d.Grants().RedeemAuthorizationCode(ctx, storage.AuthorizationCodeRedemption{CodeHash: code, ClientID: "c"})
			return err
		},
		check: func(t *testing.T, err error) {
			t.Helper()
			var reused *storage.AuthorizationCodeAlreadyRedeemedError
			if !errors.As(err, &reused) {
				t.Fatalf("losing a race = %v, want *AuthorizationCodeAlreadyRedeemedError", err)
			}
		},
	}, {
		name: "record issued token", setup: createCode,
		change: "UPDATE {p}authorization_codes SET redeemed = 1 WHERE code_hash = $1", arg: code[:],
		call: func(d *sqlstore.DB) error {
			return d.Grants().RecordIssuedAccessToken(ctx, code, "at", time.Now().Add(time.Hour))
		},
		check: wantNil,
	}, {
		name: "record issued tokens", setup: createCode,
		change: "UPDATE {p}authorization_codes SET redeemed = 1 WHERE code_hash = $1", arg: code[:],
		call: func(d *sqlstore.DB) error {
			return d.Grants().RecordIssuedTokens(ctx, code, "at", time.Now().Add(time.Hour), token, time.Now().Add(time.Hour))
		},
		check: wantNil,
	}, {
		name: "revoke refresh token",
		setup: func(t *testing.T, d *sqlstore.DB) {
			t.Helper()
			must(t, d.Grants().CreateRefreshToken(ctx, storage.NewRefreshToken{TokenHash: token, ClientID: "c", Grant: secretGrant, ExpiresAt: time.Now().Add(time.Minute)}))
		},
		change: "DELETE FROM {p}refresh_tokens WHERE token_hash = $1", arg: token[:],
		call:  func(d *sqlstore.DB) error { return d.Grants().RevokeRefreshToken(ctx, token) },
		check: wantNil,
	}, {
		name:   "use once",
		change: "INSERT INTO {p}replay (namespace, digest, sweep_after) VALUES ('n', $1, 0)", arg: digest[:],
		call: func(d *sqlstore.DB) error {
			return d.Replay().UseOnce(ctx, storage.ReplayUse{Namespace: "n", Digest: digest, ExpiresAt: time.Now().Add(time.Minute)})
		},
		check: func(t *testing.T, err error) {
			t.Helper()
			if !errors.Is(err, sqlstore.ErrReplayed) || errors.Is(err, storage.ErrStoreUnavailable) {
				t.Fatalf("losing a race = %v, want ErrReplayed, not an outage", err)
			}
		},
	}, {
		name:   "pairwise subject",
		change: "INSERT INTO {p}pairwise_subjects (issuer, sector, subject, body) VALUES ('i', 's', 'u', $1)", arg: "winner",
		call: func(d *sqlstore.DB) error {
			body, err := d.PairwiseSubjects().GetOrCreate(ctx, storage.PairwiseSubjectKey{Issuer: "i", Sector: "s", Subject: "u"}, "loser")
			if err == nil && body != "winner" {
				return errors.New("GetOrCreate losing a race returned " + body + ", want the winner's body")
			}
			return err
		},
		check: wantNil,
	}, {
		name:   "revoke",
		change: "INSERT INTO {p}revocations (revocation_key, sweep_after) VALUES ($1, 0)", arg: "key",
		call:  func(d *sqlstore.DB) error { return d.Revocation().Revoke(ctx, "key", time.Now().Add(time.Hour)) },
		check: wantNil,
	}}
}

// On a database whose default isolation is REPEATABLE READ or
// SERIALIZABLE, a single-statement write that loses a race still gets
// its typed outcome, never an outage, and changes nothing twice:
// whether the handle runs it on its own, rerunning it at READ
// COMMITTED after its serialization failure, or — having read the
// default in CheckSchema — at READ COMMITTED from the start.
func TestPostgresSingleStatementRaces(t *testing.T) {
	for _, level := range []string{"repeatable read", "serializable"} {
		for _, checked := range []bool{false, true} {
			for _, race := range singleStatementRaces() {
				t.Run(fmt.Sprintf("%s/checked=%v/%s", level, checked, race.name), func(t *testing.T) {
					p, d := isolationPlace(t, level, checked)
					if race.setup != nil {
						race.setup(t, d)
					}
					change := strings.ReplaceAll(race.change, "{p}", p.prefix)
					race.check(t, raceLockedRow(t, change, race.arg, func() error { return race.call(d) }))
				})
			}
		}
	}
}

// On a database whose default isolation is READ COMMITTED, Migrate and
// CheckSchema leave single-statement writes to run on their own.
func TestPostgresReadCommittedDefaultIsNotPinned(t *testing.T) {
	if postgresDSN == "" {
		t.Skip("PostgreSQL only: " + postgresDSNEnv + " is unset")
	}
	p := newPlace(t, sqlstore.Postgres)
	d := p.migrated()
	if sqlstore.PinsIsolation(d) {
		t.Fatal("PinsIsolation after Migrate on a READ COMMITTED database = true, want false")
	}
	must(t, d.CheckSchema(context.Background()))
	if sqlstore.PinsIsolation(d) {
		t.Fatal("PinsIsolation after CheckSchema on a READ COMMITTED database = true, want false")
	}
}

// On a database whose default isolation is REPEATABLE READ or
// SERIALIZABLE, of concurrent single-statement consumes of one key
// through a handle that runs them on its own, exactly one wins and every
// other gets its typed outcome: none is an outage, and none consumes
// twice.
func TestPostgresConcurrentConsumesUnderStricterIsolation(t *testing.T) {
	const callers = 24
	ctx := context.Background()
	for _, level := range []string{"repeatable read", "serializable"} {
		t.Run(level, func(t *testing.T) {
			_, d := isolationPlace(t, level, false)
			code := sha256.Sum256([]byte("contended code"))
			must(t, d.Grants().CreateAuthorizationCode(ctx, storage.NewAuthorizationCode{CodeHash: code, ClientID: "c", Grant: secretGrant, ExpiresAt: time.Now().Add(time.Minute)}))
			use := storage.ReplayUse{Namespace: "n", Digest: sha256.Sum256([]byte("contended jti")), ExpiresAt: time.Now().Add(time.Minute)}
			redeems := concurrently(callers, func() error {
				_, err := d.Grants().RedeemAuthorizationCode(ctx, storage.AuthorizationCodeRedemption{CodeHash: code, ClientID: "c"})
				return err
			})
			uses := concurrently(callers, func() error { return d.Replay().UseOnce(ctx, use) })
			checkOneWinner(t, "RedeemAuthorizationCode", redeems, func(err error) bool {
				var reused *storage.AuthorizationCodeAlreadyRedeemedError
				return errors.As(err, &reused)
			})
			checkOneWinner(t, "UseOnce", uses, func(err error) bool {
				return errors.Is(err, sqlstore.ErrReplayed) && !errors.Is(err, storage.ErrStoreUnavailable)
			})
		})
	}
}

// concurrently runs call n times at once, returning their errors.
func concurrently(n int, call func() error) []error {
	errs := make([]error, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs[i] = call()
		}()
	}
	close(start)
	wg.Wait()
	return errs
}

// checkOneWinner requires exactly one of errs to be nil, and every
// other to be a loser's outcome.
func checkOneWinner(t *testing.T, what string, errs []error, lost func(error) bool) {
	t.Helper()
	winners := 0
	for _, err := range errs {
		switch {
		case err == nil:
			winners++
		case !lost(err):
			t.Errorf("%s: a concurrent call = %v, want a loser's typed outcome", what, err)
		}
	}
	if winners != 1 {
		t.Errorf("%s: %d of %d concurrent calls won, want exactly 1", what, winners, len(errs))
	}
}

// TestPostgresIsolationCheckFailureKeepsPin checks that a failed read of
// the default isolation level is an error, and leaves a handle that
// pinned READ COMMITTED still pinning it.
func TestPostgresIsolationCheckFailureKeepsPin(t *testing.T) {
	_, d := isolationPlace(t, "serializable", true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := sqlstore.CheckIsolation(ctx, d)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("CheckIsolation with a cancelled context = %v, want context.Canceled", err)
	}
	if !sqlstore.PinsIsolation(d) {
		t.Fatal("PinsIsolation after a failed check = false, want true")
	}
}

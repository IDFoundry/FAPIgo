package sqlstore_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/sqlstore"
	"github.com/idfoundry/fapigo/storage"
)

func TestNewRefusesBadOptions(t *testing.T) {
	_, db := newPlace(t, sqlstore.SQLite).open()
	for name, c := range map[string]struct {
		dialect sqlstore.Dialect
		opts    sqlstore.Options
		nilDB   bool
	}{
		"nil db":            {sqlstore.SQLite, sqlstore.Options{}, true},
		"no dialect":        {0, sqlstore.Options{}, false},
		"unknown dialect":   {3, sqlstore.Options{}, false},
		"upper-case prefix": {sqlstore.SQLite, sqlstore.Options{TablePrefix: "Fapigo_"}, false},
		"quoting prefix":    {sqlstore.SQLite, sqlstore.Options{TablePrefix: `x"; DROP TABLE y; --`}, false},
		"space in prefix":   {sqlstore.SQLite, sqlstore.Options{TablePrefix: "a b"}, false},
		"digit first":       {sqlstore.SQLite, sqlstore.Options{TablePrefix: "1x"}, false},
		"underscore first":  {sqlstore.SQLite, sqlstore.Options{TablePrefix: "_x"}, false},
		"hyphen":            {sqlstore.SQLite, sqlstore.Options{TablePrefix: "a-b"}, false},
		"too long":          {sqlstore.SQLite, sqlstore.Options{TablePrefix: "a23456789012345678901234567890123"}, false},
		"negative timeout":  {sqlstore.SQLite, sqlstore.Options{SQLiteBusyTimeout: -time.Second}, false},
	} {
		d := db
		if c.nilDB {
			d = nil
		}
		if _, err := sqlstore.New(d, c.dialect, c.opts); err == nil {
			t.Errorf("%s: New = nil error, want an error", name)
		}
	}
	for _, prefix := range []string{"", "a", "fapigo_", "a23456789012345678901234567890_2"} {
		if _, err := sqlstore.New(db, sqlstore.Postgres, sqlstore.Options{TablePrefix: prefix}); err != nil {
			t.Errorf("New(TablePrefix %q) = %v, want nil", prefix, err)
		}
	}
}

func TestDialectString(t *testing.T) {
	for d, want := range map[sqlstore.Dialect]string{sqlstore.Postgres: "postgres", sqlstore.SQLite: "sqlite", 7: "Dialect(7)"} {
		if got := d.String(); got != want {
			t.Errorf("Dialect(%d).String() = %q, want %q", int(d), got, want)
		}
	}
}

// Migrate is idempotent, including from several handles at once: each
// migration applies once.
func TestMigrateIsIdempotent(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		ctx := context.Background()
		p := newPlace(t, dialect)
		d := p.migrated()
		if err := d.Migrate(ctx); err != nil {
			t.Fatalf("second Migrate: %v", err)
		}
		var wg sync.WaitGroup
		errs := make([]error, 4)
		for i := range errs {
			h, _ := p.openPool()
			wg.Go(func() { errs[i] = h.Migrate(ctx) })
		}
		wg.Wait()
		if err := errors.Join(errs...); err != nil {
			t.Fatalf("concurrent Migrate: %v", err)
		}
		if err := d.CheckSchema(ctx); err != nil {
			t.Fatalf("CheckSchema after Migrate: %v", err)
		}
		_, db := p.open()
		var applied int
		if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+p.prefix+"schema_migrations").Scan(&applied); err != nil {
			t.Fatal(err)
		}
		if applied != sqlstore.SchemaVersion() {
			t.Fatalf("schema_migrations has %d rows, want %d", applied, sqlstore.SchemaVersion())
		}
	})
}

// Migrate is safe from several processes at once on a brand-new SQLite
// file too, opened with the DSN the package documentation recommends:
// switching a new file to WAL mode takes its write lock as each
// connection opens, failing with SQLITE_BUSY for the others, which
// Migrate waits out.
func TestConcurrentFirstMigrate(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		for range 5 {
			p := newPlace(t, dialect)
			var wg sync.WaitGroup
			errs := make([]error, 6)
			for i := range errs {
				h, _ := p.openPool()
				wg.Go(func() { errs[i] = h.Migrate(context.Background()) })
			}
			wg.Wait()
			if err := errors.Join(errs...); err != nil {
				t.Fatalf("concurrent first Migrate: %v", err)
			}
		}
	})
}

// CheckSchema refuses a database Migrate hasn't run on, one missing a
// migration, and one a newer release migrated further; Migrate refuses
// the last too.
func TestCheckSchemaRefusals(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		ctx := context.Background()
		p := newPlace(t, dialect)
		d, db := p.open()
		if err := d.CheckSchema(ctx); err == nil {
			t.Fatal("CheckSchema before Migrate = nil error, want an error")
		}
		if err := d.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		table := p.prefix + "schema_migrations"
		if _, err := db.ExecContext(ctx, "INSERT INTO "+table+" (version, name, applied_at) VALUES (999, '0999_future.sql', 0)"); err != nil {
			t.Fatal(err)
		}
		if err := d.CheckSchema(ctx); err == nil {
			t.Error("CheckSchema of a newer schema = nil error, want an error")
		}
		if err := d.Migrate(ctx); err == nil {
			t.Error("Migrate of a newer schema = nil error, want an error")
		}
		if _, err := db.ExecContext(ctx, "DELETE FROM "+table); err != nil {
			t.Fatal(err)
		}
		if err := d.CheckSchema(ctx); err == nil {
			t.Error("CheckSchema with no migration recorded = nil error, want an error")
		}
	})
}

// withSQLite runs fn on a DB over the SQLite file at path opened with
// DSN query query (with its "?", or empty), closing it after.
func withSQLite(t *testing.T, path, query string, fn func(d *sqlstore.DB) error) error {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+query)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	d, err := sqlstore.New(db, sqlstore.SQLite, sqlstore.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return fn(d)
}

// Migrate and CheckSchema refuse a SQLite database that isn't in WAL
// mode, whose reads fail with SQLITE_BUSY while a write commits, with
// an error naming the DSN that fixes it; a file once switched to WAL
// mode stays in it, whatever DSN opens it next.
func TestSQLiteRequiresWAL(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "store.db")
	migrate := func(d *sqlstore.DB) error { return d.Migrate(ctx) }
	checkSchema := func(d *sqlstore.DB) error { return d.CheckSchema(ctx) }
	for _, query := range []string{"", "?_pragma=busy_timeout(10000)", "?_pragma=journal_mode(DELETE)", "?_pragma=journal_mode(TRUNCATE)"} {
		wantNotWAL(t, "Migrate("+query+")", withSQLite(t, path, query, migrate))
	}
	if err := withSQLite(t, path, "?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)", migrate); err != nil {
		t.Fatalf("Migrate in WAL mode: %v", err)
	}
	if err := withSQLite(t, path, "", checkSchema); err != nil {
		t.Fatalf("CheckSchema of a WAL file opened without the pragma: %v", err)
	}
	wantNotWAL(t, "CheckSchema(after switching back to a rollback journal)", withSQLite(t, path, "?_pragma=journal_mode(DELETE)", checkSchema))
}

// wantNotWAL fails t unless err is checkJournalMode's refusal.
func wantNotWAL(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), "not WAL") || !strings.Contains(err.Error(), "_pragma=journal_mode(WAL)") {
		t.Errorf("%s = %v, want a refusal naming journal_mode(WAL)", what, err)
	}
}

// Two prefixes in one database are two separate sets of stores.
func TestTablePrefixesKeepStoresApart(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		ctx := context.Background()
		p := newPlace(t, dialect)
		a := p.migrated()
		p.prefix = "other_" + p.prefix
		b := p.migrated()
		digest := sha256.Sum256([]byte("jti"))
		use := storage.ReplayUse{Namespace: "test", Digest: digest, ExpiresAt: time.Now().Add(time.Minute)}
		if err := a.Replay().UseOnce(ctx, use); err != nil {
			t.Fatal(err)
		}
		if err := b.Replay().UseOnce(ctx, use); err != nil {
			t.Fatalf("UseOnce under another prefix = %v, want nil", err)
		}
	})
}

// A consume is atomic across handles — separate pools, as separate
// processes have — not only within one: of concurrent redemptions of
// one code through several handles, exactly one wins.
func TestConsumeIsAtomicAcrossHandles(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		ctx := context.Background()
		p := newPlace(t, dialect)
		hash := sha256.Sum256([]byte("code"))
		if err := p.migrated().Grants().CreateAuthorizationCode(ctx, storage.NewAuthorizationCode{
			CodeHash: hash, ClientID: "client-1", ExpiresAt: time.Now().Add(time.Minute),
		}); err != nil {
			t.Fatal(err)
		}
		var handles []*sqlstore.GrantStore
		for range 4 {
			d, _ := p.openPool()
			handles = append(handles, d.Grants())
		}
		var wg sync.WaitGroup
		var mu sync.Mutex
		wins := 0
		for i := range 20 {
			g := handles[i%len(handles)]
			wg.Go(func() {
				if _, err := g.RedeemAuthorizationCode(ctx, storage.AuthorizationCodeRedemption{CodeHash: hash}); err == nil {
					mu.Lock()
					wins++
					mu.Unlock()
				}
			})
		}
		wg.Wait()
		if wins != 1 {
			t.Fatalf("concurrent redemptions across handles won %d times, want exactly 1", wins)
		}
	})
}

// A database that can't answer is an outage — the error wraps
// storage.ErrStoreUnavailable — never the interfaces' "unknown",
// "replayed" or "unknown client".
func TestDatabaseFailureIsStoreUnavailable(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		ctx := context.Background()
		p := newPlace(t, dialect)
		p.prefix = "never_migrated_" + p.prefix
		d, _ := p.open() // tables never created: every statement fails
		digest := sha256.Sum256([]byte("x"))
		later := time.Now().Add(time.Minute)
		calls := writesOn(d)
		for name, call := range map[string]func() error{
			"UseOnce": func() error {
				return d.Replay().UseOnce(ctx, storage.ReplayUse{Namespace: "n", Digest: digest, ExpiresAt: later})
			},
			"Lookup": func() error {
				_, err := d.Nonces().Lookup(ctx, storage.NonceLookup{Nonce: "n"})
				return err
			},
			"IsRevoked": func() error {
				_, err := d.Revocation().IsRevoked(ctx, "k")
				return err
			},
			"ResolveClient": func() error {
				_, err := d.Clients().ResolveClient(ctx, "client-1")
				return err
			},
			"RedeemAuthorizationCode": func() error {
				_, err := d.Grants().RedeemAuthorizationCode(ctx, storage.AuthorizationCodeRedemption{CodeHash: digest})
				return err
			},
			"BeginAuthorization": func() error {
				_, err := d.Transactions().BeginAuthorization(ctx, storage.BeginAuthorizationTransaction{Reference: "r", Handle: "h", HandleExpiresAt: later, Now: time.Now()})
				return err
			},
			"CompleteAuthorization": func() error {
				_, err := d.Transactions().CompleteAuthorization(ctx, storage.CompleteAuthorizationTransaction{Handle: "h"})
				return err
			},
			"Sweep": func() error {
				_, err := d.Sweep(ctx, time.Now())
				return err
			},
			"LookupAccessToken": func() error {
				_, err := d.AccessTokens().LookupAccessToken(ctx, storage.AccessTokenLookup{TokenHash: digest})
				return err
			},
			"LookupBackchannelAuthentication": func() error {
				_, err := d.Backchannel().LookupBackchannelAuthentication(ctx, digest)
				return err
			},
			"PollBackchannelAuthentication": func() error {
				_, err := d.Backchannel().PollBackchannelAuthentication(ctx, storage.PollBackchannelAuthentication{AuthReqIDHash: digest, Now: time.Now()})
				return err
			},
			"ConsumeSession": func() error {
				_, err := d.Sessions().Consume(ctx, storage.SessionConsumption{State: "s"})
				return err
			},
			"LookupPairwiseSubject": func() error {
				_, err := d.PairwiseSubjects().Lookup(ctx, "i", "s", "b")
				return err
			},
		} {
			calls[name] = call
		}
		for name, call := range calls {
			if err := call(); !errors.Is(err, storage.ErrStoreUnavailable) || errors.Is(err, sqlstore.ErrNotFound) {
				t.Errorf("%s on missing tables = %v, want an error wrapping storage.ErrStoreUnavailable only", name, err)
			}
		}
	})
}

// A cancelled context's error stays recognizable as one.
func TestCancelledContextIsReported(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		d := freshDB(t, dialect)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := d.Replay().UseOnce(ctx, storage.ReplayUse{Namespace: "n", Digest: sha256.Sum256([]byte("x")), ExpiresAt: time.Now().Add(time.Minute)})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("UseOnce with a cancelled context = %v, want context.Canceled", err)
		}
	})
}

// A key PostgreSQL's text can't hold (NUL, invalid UTF-8) — a DPoP
// proof's nonce claim, say, is the presenter's choice — is answered as
// unknown on every dialect, not as an outage, and refused on write.
func TestUnstorableTextKeys(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		d := freshDB(t, dialect)
		for _, key := range []string{"a\x00b", "\xff"} {
			checkUnstorableReadsUnknown(t, d, key)
			checkUnstorableWritesRefused(t, d, key)
		}
	})
}

// checkUnstorableReadsUnknown checks that each lookup answers key as
// unknown.
func checkUnstorableReadsUnknown(t *testing.T, d *sqlstore.DB, key string) {
	t.Helper()
	ctx := context.Background()
	later := time.Now().Add(time.Minute)
	if _, err := d.Nonces().Lookup(ctx, storage.NonceLookup{Nonce: key}); !errors.Is(err, sqlstore.ErrNotFound) {
		t.Errorf("Lookup(%q) = %v, want ErrNotFound", key, err)
	}
	if revoked, err := d.Revocation().IsRevoked(ctx, key); err != nil || revoked {
		t.Errorf("IsRevoked(%q) = %v, %v, want false, nil", key, revoked, err)
	}
	if _, err := d.Clients().ResolveClient(ctx, fapi.ClientID(key)); !errors.Is(err, sqlstore.ErrNotFound) {
		t.Errorf("ResolveClient(%q) = %v, want ErrNotFound", key, err)
	}
	if _, err := d.Transactions().BeginAuthorization(ctx, storage.BeginAuthorizationTransaction{Reference: key, Handle: "h", HandleExpiresAt: later, Now: time.Now()}); !errors.Is(err, sqlstore.ErrNotFound) {
		t.Errorf("BeginAuthorization(%q) = %v, want ErrNotFound", key, err)
	}
	if _, err := d.Transactions().CompleteAuthorization(ctx, storage.CompleteAuthorizationTransaction{Handle: key}); !errors.Is(err, sqlstore.ErrNotFound) {
		t.Errorf("CompleteAuthorization(%q) = %v, want ErrNotFound", key, err)
	}
	if _, err := d.Sessions().Consume(ctx, storage.SessionConsumption{State: key}); !errors.Is(err, sqlstore.ErrNotFound) {
		t.Errorf("Consume(%q) = %v, want ErrNotFound", key, err)
	}
	for _, args := range [][3]string{{key, "s", "b"}, {"i", key, "b"}, {"i", "s", key}} {
		if _, err := d.PairwiseSubjects().Lookup(ctx, args[0], args[1], args[2]); !errors.Is(err, storage.ErrPairwiseSubjectNotFound) || !errors.Is(err, sqlstore.ErrNotFound) {
			t.Errorf("PairwiseSubjects().Lookup(%q) = %v, want ErrPairwiseSubjectNotFound", args, err)
		}
	}
}

// checkUnstorableWritesRefused checks that each write refuses key,
// without wrapping storage.ErrStoreUnavailable.
func checkUnstorableWritesRefused(t *testing.T, d *sqlstore.DB, key string) {
	t.Helper()
	ctx := context.Background()
	later := time.Now().Add(time.Minute)
	for name, err := range map[string]error{
		"Issue":                   d.Nonces().Issue(ctx, storage.NonceIssuance{Nonce: key, ExpiresAt: later}),
		"Revoke":                  d.Revocation().Revoke(ctx, key, later),
		"CreatePAR":               d.Transactions().CreatePAR(ctx, storage.NewPARRecord{Reference: key, ClientID: "c", ExpiresAt: later}),
		"CreateAuthorizationCode": d.Grants().CreateAuthorizationCode(ctx, storage.NewAuthorizationCode{ClientID: fapi.ClientID(key), ExpiresAt: later}),
		"CreateRefreshToken":      d.Grants().CreateRefreshToken(ctx, storage.NewRefreshToken{ClientID: fapi.ClientID(key), ExpiresAt: later}),
		"UseOnce":                 d.Replay().UseOnce(ctx, storage.ReplayUse{Namespace: storage.ReplayNamespace(key), ExpiresAt: later}),
		"RecordIssuedAccessToken": d.Grants().RecordIssuedAccessToken(ctx, [32]byte{}, key, later),
		"CreateAccessToken":       d.AccessTokens().CreateAccessToken(ctx, storage.NewAccessToken{ClientID: fapi.ClientID(key), ExpiresAt: later}),
		"CreateBackchannelAuthentication": d.Backchannel().CreateBackchannelAuthentication(ctx, storage.NewBackchannelAuthentication{
			ClientID: fapi.ClientID(key), DeliveryMode: "poll", ExpiresAt: later,
		}),
		"GetOrCreatePairwiseSubject": getOrCreateErr(d, storage.PairwiseSubjectKey{Issuer: "i", Sector: "s", Subject: key}, "b"),
		"GetOrCreatePairwiseBody":    getOrCreateErr(d, storage.PairwiseSubjectKey{Issuer: "i", Sector: "s", Subject: "u"}, key),
		"CreateSession":              d.Sessions().Create(ctx, storage.NewSession{State: key, ExpiresAt: later}),
	} {
		if err == nil || errors.Is(err, storage.ErrStoreUnavailable) {
			t.Errorf("%s(%q) = %v, want a refusal", name, key, err)
		}
	}
}

// A redemption by another client — including one by a client_id no
// code could have been issued to — is refused without redeeming the
// code. (The contract suite skips that check for a store that ignores
// AuthorizationCodeRedemption.ClientID; this one mustn't.)
func TestRedeemByAnotherClientLeavesCodeUnredeemed(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		ctx := context.Background()
		g := freshDB(t, dialect).Grants()
		hash := sha256.Sum256([]byte("code"))
		must(t, g.CreateAuthorizationCode(ctx, storage.NewAuthorizationCode{CodeHash: hash, ClientID: "c", ExpiresAt: time.Now().Add(time.Minute)}))
		for _, other := range []fapi.ClientID{"c2", "C", "c\x00"} {
			if _, err := g.RedeemAuthorizationCode(ctx, storage.AuthorizationCodeRedemption{CodeHash: hash, ClientID: other}); err == nil {
				t.Fatalf("RedeemAuthorizationCode by client %q = nil error, want a refusal", other)
			}
		}
		if _, err := g.RedeemAuthorizationCode(ctx, storage.AuthorizationCodeRedemption{CodeHash: hash, ClientID: "c"}); err != nil {
			t.Fatalf("RedeemAuthorizationCode by its own client afterwards = %v, want nil", err)
		}
	})
}

// Recording a token issued for a code the store doesn't hold is an
// error, not silently nothing.
func TestRecordIssuedForUnknownCode(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		ctx := context.Background()
		d := freshDB(t, dialect)
		if d.Dialect() != dialect {
			t.Fatalf("Dialect() = %v, want %v", d.Dialect(), dialect)
		}
		g := d.Grants()
		unknown := sha256.Sum256([]byte("unknown"))
		later := time.Now().Add(time.Minute)
		if err := g.RecordIssuedAccessToken(ctx, unknown, "at", later); !errors.Is(err, sqlstore.ErrNotFound) {
			t.Errorf("RecordIssuedAccessToken(unknown code) = %v, want ErrNotFound", err)
		}
		if err := g.RecordIssuedRefreshToken(ctx, unknown, unknown, later); !errors.Is(err, sqlstore.ErrNotFound) {
			t.Errorf("RecordIssuedRefreshToken(unknown code) = %v, want ErrNotFound", err)
		}
	})
}

// writesOn is a call of each of d's writes, for
// TestDatabaseFailureIsStoreUnavailable.
func writesOn(d *sqlstore.DB) map[string]func() error {
	ctx := context.Background()
	later := time.Now().Add(time.Minute)
	digest := sha256.Sum256([]byte("x"))
	return map[string]func() error{
		"CreatePAR": func() error {
			return d.Transactions().CreatePAR(ctx, storage.NewPARRecord{Reference: "r", ClientID: "c", ExpiresAt: later})
		},
		"CreateAuthorizationCode": func() error {
			return d.Grants().CreateAuthorizationCode(ctx, storage.NewAuthorizationCode{CodeHash: digest, ClientID: "c", ExpiresAt: later})
		},
		"RecordIssuedAccessToken":  func() error { return d.Grants().RecordIssuedAccessToken(ctx, digest, "k", later) },
		"RecordIssuedRefreshToken": func() error { return d.Grants().RecordIssuedRefreshToken(ctx, digest, digest, later) },
		"CreateRefreshToken": func() error {
			return d.Grants().CreateRefreshToken(ctx, storage.NewRefreshToken{TokenHash: digest, ClientID: "c", ExpiresAt: later})
		},
		"RedeemRefreshToken": func() error {
			_, err := d.Grants().RedeemRefreshToken(ctx, storage.RefreshTokenRedemption{TokenHash: digest})
			return err
		},
		"RevokeRefreshToken": func() error { return d.Grants().RevokeRefreshToken(ctx, digest) },
		"Issue":              func() error { return d.Nonces().Issue(ctx, storage.NonceIssuance{Nonce: "n", ExpiresAt: later}) },
		"Revoke":             func() error { return d.Revocation().Revoke(ctx, "k", later) },
		"Put": func() error {
			return d.Clients().Put(ctx, storage.RegisteredClientConfig{ID: "c", RedirectURIs: []fapi.RegisteredRedirectURI{"https://rp.example/cb"}, ClientAssertionAlgorithm: fapi.ES256})
		},
		"Delete": func() error {
			_, err := d.Clients().Delete(ctx, "c")
			return err
		},
		"CreateAccessToken": func() error {
			return d.AccessTokens().CreateAccessToken(ctx, storage.NewAccessToken{TokenHash: digest, ClientID: "c", ExpiresAt: later})
		},
		"CreateBackchannelAuthentication": func() error {
			return d.Backchannel().CreateBackchannelAuthentication(ctx, storage.NewBackchannelAuthentication{AuthReqIDHash: digest, HandleHash: digest, ClientID: "c", DeliveryMode: "poll", ExpiresAt: later})
		},
		"DecideBackchannelAuthentication": func() error {
			_, err := d.Backchannel().DecideBackchannelAuthentication(ctx, storage.DecideBackchannelAuthentication{HandleHash: digest, Status: storage.BackchannelAuthenticationDenied})
			return err
		},
		"GetOrCreatePairwiseSubject": func() error {
			_, err := d.PairwiseSubjects().GetOrCreate(ctx, storage.PairwiseSubjectKey{Issuer: "i", Sector: "s", Subject: "u"}, "b")
			return err
		},
		"CreateSession": func() error {
			return d.Sessions().Create(ctx, storage.NewSession{State: "s", ExpiresAt: later})
		},
	}
}

// Migrate, CheckSchema and Sweep report a database they can't reach.
func TestClosedDatabase(t *testing.T) {
	ctx := context.Background()
	d, db := newPlace(t, sqlstore.SQLite).openPool()
	_ = db.Close()
	if err := d.Migrate(ctx); err == nil {
		t.Error("Migrate on a closed database = nil error, want an error")
	}
	if err := d.CheckSchema(ctx); err == nil {
		t.Error("CheckSchema on a closed database = nil error, want an error")
	}
	if _, err := d.Sweep(ctx, time.Now()); !errors.Is(err, storage.ErrStoreUnavailable) {
		t.Errorf("Sweep on a closed database = %v, want ErrStoreUnavailable", err)
	}
}

// getOrCreateErr is GetOrCreate's error.
func getOrCreateErr(d *sqlstore.DB, key storage.PairwiseSubjectKey, candidate string) error {
	_, err := d.PairwiseSubjects().GetOrCreate(context.Background(), key, candidate)
	return err
}

// Writes refuse what the stores can't keep: an access token's unknown
// sender constraint, a CIBA delivery mode other than poll or ping, and
// a decision that isn't one.
func TestInvalidRecordsRefused(t *testing.T) {
	ctx := context.Background()
	d := freshDB(t, sqlstore.SQLite)
	later := time.Now().Add(time.Minute)
	for name, err := range map[string]error{
		"CreateAccessToken(unknown sender constrain)": d.AccessTokens().CreateAccessToken(ctx, storage.NewAccessToken{ClientID: "c", SenderConstrain: 9, ExpiresAt: later}),
		"CreateBackchannelAuthentication(push)": d.Backchannel().CreateBackchannelAuthentication(ctx, storage.NewBackchannelAuthentication{
			ClientID: "c", DeliveryMode: "push", ExpiresAt: later,
		}),
	} {
		if err == nil || errors.Is(err, storage.ErrStoreUnavailable) {
			t.Errorf("%s = %v, want a refusal", name, err)
		}
	}
	for _, status := range []storage.BackchannelAuthenticationStatus{0, storage.BackchannelAuthenticationPending, 9} {
		if _, err := d.Backchannel().DecideBackchannelAuthentication(ctx, storage.DecideBackchannelAuthentication{Status: status}); err == nil || errors.Is(err, storage.ErrStoreUnavailable) {
			t.Errorf("DecideBackchannelAuthentication(status %d) = %v, want a refusal", status, err)
		}
	}
}

// A SQLite write waiting for another of its DB's writes stops waiting
// once its context ends, as an outage wrapping the context's error,
// rather than waiting its turn.
func TestSQLiteWriteWaitEndsWithItsContext(t *testing.T) {
	d := freshDB(t, sqlstore.SQLite)
	use := storage.ReplayUse{Namespace: "n", Digest: sha256.Sum256([]byte("waiting")), ExpiresAt: time.Now().Add(time.Minute)}
	release := sqlstore.HoldSQLiteWrites(d)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := d.Replay().UseOnce(ctx, use)
	if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, storage.ErrStoreUnavailable) {
		t.Fatalf("UseOnce waiting past its deadline = %v, want context.DeadlineExceeded as an outage", err)
	}
	if waited := time.Since(start); waited > 5*time.Second {
		t.Fatalf("UseOnce waited %v past its deadline", waited)
	}
	release()
	must(t, d.Replay().UseOnce(context.Background(), use))
}

// A SQLite write sets Options.SQLiteBusyTimeout on its connection once,
// not before every write.
func TestSQLiteBusyTimeoutIsSetOncePerConnection(t *testing.T) {
	ctx := context.Background()
	p := newPlace(t, sqlstore.SQLite)
	_, db := p.openPool()
	db.SetMaxOpenConns(1)
	d := p.handleWith(db, sqlstore.Options{SQLiteBusyTimeout: 1234 * time.Millisecond})
	must(t, d.Migrate(ctx))
	busyTimeout := func() int {
		t.Helper()
		var ms int
		if err := db.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&ms); err != nil {
			t.Fatal(err)
		}
		return ms
	}
	if ms := busyTimeout(); ms != 1234 {
		t.Fatalf("busy_timeout after a write = %d, want 1234", ms)
	}
	if _, err := db.ExecContext(ctx, "PRAGMA busy_timeout = 777"); err != nil {
		t.Fatal(err)
	}
	must(t, d.Replay().UseOnce(ctx, storage.ReplayUse{Namespace: "n", Digest: sha256.Sum256([]byte("once")), ExpiresAt: time.Now().Add(time.Minute)}))
	if ms := busyTimeout(); ms != 777 {
		t.Fatalf("busy_timeout after another write on the same connection = %d, want 777: set again", ms)
	}
}

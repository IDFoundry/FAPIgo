package sqlstore_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/sqlstore"
	"github.com/idfoundry/fapigo/storage"
)

// batchingRevocation is d's BatchingRevocation() as the
// storage.RevocationBatchChecker it is.
func batchingRevocation(t *testing.T, d *sqlstore.DB) interface {
	storage.RevocationStore
	storage.RevocationBatchChecker
} {
	t.Helper()
	r, ok := d.BatchingRevocation().(interface {
		storage.RevocationStore
		storage.RevocationBatchChecker
	})
	if !ok {
		t.Fatal("BatchingRevocation() isn't a storage.RevocationBatchChecker")
	}
	return r
}

// batchingGrants is d's BatchingGrants() as the
// storage.IssuedTokensRecorder it is.
func batchingGrants(t *testing.T, d *sqlstore.DB) interface {
	storage.GrantStore
	storage.IssuedTokensRecorder
} {
	t.Helper()
	g, ok := d.BatchingGrants().(interface {
		storage.GrantStore
		storage.IssuedTokensRecorder
	})
	if !ok {
		t.Fatal("BatchingGrants() isn't a storage.IssuedTokensRecorder")
	}
	return g
}

// The stores themselves aren't the optional interfaces — only what
// DB.BatchingRevocation and DB.BatchingGrants return are — and neither
// is a wrapper that embeds one, or that embeds what those return: such
// a wrapper, overriding IsRevoked or RecordIssued*, would otherwise have
// the server call the inner store's batch method, past its overrides.
func TestBatchMethodsAreNotPromoted(t *testing.T) {
	type embedsRevocation struct{ *sqlstore.RevocationStore }
	type embedsGrants struct{ *sqlstore.GrantStore }
	type embedsBatchingRevocation struct{ storage.RevocationStore }
	type embedsBatchingGrants struct{ storage.GrantStore }
	d := freshDB(t, sqlstore.SQLite)
	for name, v := range map[string]any{
		"*RevocationStore":                        d.Revocation(),
		"a struct embedding *RevocationStore":     embedsRevocation{d.Revocation()},
		"a struct embedding BatchingRevocation()": embedsBatchingRevocation{d.BatchingRevocation()},
	} {
		if _, ok := v.(storage.RevocationBatchChecker); ok {
			t.Errorf("%s is a storage.RevocationBatchChecker", name)
		}
	}
	for name, v := range map[string]any{
		"*GrantStore":                         d.Grants(),
		"a struct embedding *GrantStore":      embedsGrants{d.Grants()},
		"a struct embedding BatchingGrants()": embedsBatchingGrants{d.BatchingGrants()},
	} {
		if _, ok := v.(storage.IssuedTokensRecorder); ok {
			t.Errorf("%s is a storage.IssuedTokensRecorder", name)
		}
	}
}

// Nor can a wrapper embedding a store reach the batching store through
// it: the stores have no Batching method (as they did in v0.7.0), which
// such a wrapper would inherit and which would hand out the inner
// store's batching adapter, without the wrapper's overrides.
func TestStoresHaveNoBatchingMethod(t *testing.T) {
	type embedsRevocation struct{ *sqlstore.RevocationStore }
	type embedsGrants struct{ *sqlstore.GrantStore }
	type embedsResourceServerStores struct{ sqlstore.ResourceServerStores }
	for _, v := range []any{
		&sqlstore.RevocationStore{}, embedsRevocation{}, &embedsRevocation{},
		&sqlstore.GrantStore{}, embedsGrants{}, &embedsGrants{},
		sqlstore.ResourceServerStores{}, &embedsResourceServerStores{},
	} {
		typ := reflect.TypeOf(v)
		for i := range typ.NumMethod() {
			if name := typ.Method(i).Name; strings.Contains(name, "Batching") {
				t.Errorf("%v has a method %s", typ, name)
			}
		}
	}
}

// A wrapper of a deployment's own that embeds *RevocationStore and
// prefixes its keys sees what it revoked; DB.BatchingRevocation, its
// only way to the batched check, is reached through the DB, never the
// wrapper, so the wrapper can't hand out an adapter that skips its
// prefix. (In v0.7.0 the wrapper's promoted Batching() did, and a key
// it revoked read as not revoked there.) A wrapper wanting the batched
// check implements IsAnyRevoked itself, and the server asks that.
type tenantRevocation struct {
	*sqlstore.RevocationStore
	tenant string
}

func (r tenantRevocation) Revoke(ctx context.Context, key string, until time.Time) error {
	return r.RevocationStore.Revoke(ctx, r.tenant+"/"+key, until)
}

func (r tenantRevocation) IsRevoked(ctx context.Context, key string) (bool, error) {
	return r.RevocationStore.IsRevoked(ctx, r.tenant+"/"+key)
}

func TestWrapperCantHandOutInnerBatching(t *testing.T) {
	ctx := context.Background()
	d := freshDB(t, sqlstore.SQLite)
	var w storage.RevocationStore = tenantRevocation{d.Revocation(), "tenant-a"}
	must(t, w.Revoke(ctx, "jti-1", time.Now().Add(time.Hour)))
	if revoked, err := w.IsRevoked(ctx, "jti-1"); err != nil || !revoked {
		t.Fatalf("wrapper IsRevoked = %v, %v, want true", revoked, err)
	}
	if _, ok := w.(interface {
		Batching() storage.RevocationStore
	}); ok {
		t.Fatal("the wrapper has a Batching method, promoted from *RevocationStore")
	}
	if _, ok := w.(storage.RevocationBatchChecker); ok {
		t.Fatal("the wrapper is a storage.RevocationBatchChecker, promoted from *RevocationStore")
	}
	// The DB's batching store answers for the key as stored, the
	// wrapper's prefixed form, consistently with IsRevoked.
	if revoked, err := batchingRevocation(t, d).IsAnyRevoked(ctx, []string{"tenant-a/jti-1"}); err != nil || !revoked {
		t.Errorf("BatchingRevocation().IsAnyRevoked(the stored key) = %v, %v, want true", revoked, err)
	}
}

// What DB.BatchingRevocation and DB.BatchingGrants return keep every
// other interface the server finds on the store by type assertion:
// StoreAssurance, with the store's own Capabilities.
func TestBatchingKeepsStoreAssurance(t *testing.T) {
	for name, d := range map[string]*sqlstore.DB{"plain": freshDB(t, sqlstore.SQLite), "sealed": newPlace(t, sqlstore.SQLite).migratedWith(sqlstore.Options{Sealer: testSealer(t)})} {
		for store, pair := range map[string][2]any{
			"Revocation": {d.Revocation(), d.BatchingRevocation()},
			"Grants":     {d.Grants(), d.BatchingGrants()},
		} {
			plain, okPlain := pair[0].(storage.StoreAssurance)
			batching, ok := pair[1].(storage.StoreAssurance)
			if !okPlain || !ok || batching.Capabilities() != plain.Capabilities() {
				t.Errorf("%s Batching%s() isn't a storage.StoreAssurance with the store's Capabilities", name, store)
			}
		}
	}
}

// manyKeys is n unrevoked keys, with revoked at index at (unless at is
// out of range).
func manyKeys(n, at int, revoked string) []string {
	keys := make([]string, n)
	for i := range keys {
		keys[i] = fmt.Sprint("unrevoked-", i)
	}
	if at >= 0 && at < n {
		keys[at] = revoked
	}
	return keys
}

// IsAnyRevoked answers as IsRevoked does for each of its keys in turn:
// true for any revoked key, exactly compared, wherever it is in the
// list, past a statement's batch of keys included; false for none, for
// no keys, and for keys Revoke would refuse.
func TestIsAnyRevokedMatchesIsRevoked(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		ctx := context.Background()
		r := batchingRevocation(t, freshDB(t, dialect))
		must(t, r.Revoke(ctx, "grant:g1", time.Now().Add(time.Hour)))
		must(t, r.Revoke(ctx, "token:t1", time.Now().Add(-time.Hour))) // expired, not swept: still revoked
		for _, keys := range [][]string{
			nil,
			{},
			{"grant:g1"},
			{"grant:g2"},
			{"grant:g2", "grant:g1"},
			{"GRANT:G1", "grant:g1 ", "grant:g"},
			{"a\x00b", "\xff", "grant:g1"},
			{"a\x00b", "\xff"},
			{"token:t1", "token:t1"},
			manyKeys(16, 15, "grant:g1"),
			manyKeys(40, 35, "token:t1"),
			manyKeys(40, -1, ""),
		} {
			want := false
			for _, key := range keys {
				revoked, err := r.IsRevoked(ctx, key)
				must(t, err)
				want = want || revoked
			}
			if got, err := r.IsAnyRevoked(ctx, keys); err != nil || got != want {
				t.Errorf("IsAnyRevoked(%q) = %v, %v, want %v, nil", keys, got, err, want)
			}
		}
	})
}

// issuedRow is the issued-token columns and sweep_after of a code's
// row.
type issuedRow struct {
	accessKey   sql.NullString
	refreshHash []byte
	sweepAfter  int64
}

// readIssued reads code's issuedRow from p's tables.
func readIssued(t *testing.T, p *place, code [32]byte) issuedRow {
	t.Helper()
	_, db := p.open()
	query := "SELECT issued_access_token_key, issued_refresh_token_hash, sweep_after FROM " + p.prefix + "authorization_codes WHERE code_hash = ?"
	if p.dialect == sqlstore.Postgres {
		query = strings.Replace(query, "?", "$1", 1)
	}
	var row issuedRow
	if err := db.QueryRowContext(context.Background(), query, code[:]).Scan(&row.accessKey, &row.refreshHash, &row.sweepAfter); err != nil {
		t.Fatal(err)
	}
	return row
}

// RecordIssuedTokens leaves a code's row exactly as
// RecordIssuedAccessToken and RecordIssuedRefreshToken in turn would —
// both tokens recorded, swept no sooner than the later of their
// expiries nor than it already was — and a reuse of the code reports
// both.
func TestRecordIssuedTokensMatchesTwoCalls(t *testing.T) {
	codeExpiry := time.Now().Add(time.Minute)
	far := time.Unix(0, math.MaxInt64).Add(time.Hour)
	for _, c := range []struct {
		name            string
		access, refresh time.Time
	}{
		{"refresh later", codeExpiry.Add(time.Hour), codeExpiry.Add(24 * time.Hour)},
		{"access later", codeExpiry.Add(24 * time.Hour), codeExpiry.Add(time.Hour)},
		{"both before the retention", codeExpiry.Add(time.Second), codeExpiry.Add(2 * time.Second)},
		{"beyond the last instant", far, codeExpiry.Add(time.Hour)},
		{"zero", time.Time{}, time.Time{}},
	} {
		t.Run(c.name, func(t *testing.T) {
			forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
				checkRecordIssuedTokens(t, dialect, codeExpiry, c.access, c.refresh)
			})
		})
	}
}

// checkRecordIssuedTokens records tokens expiring at access and refresh
// for one redeemed code with the two calls and another with
// RecordIssuedTokens, and compares their rows and reuse errors.
func checkRecordIssuedTokens(t *testing.T, dialect sqlstore.Dialect, codeExpiry, access, refresh time.Time) {
	t.Helper()
	ctx := context.Background()
	p := newPlace(t, dialect)
	g := batchingGrants(t, p.migrated())
	twoCalls, oneCall := sha256.Sum256([]byte("two calls")), sha256.Sum256([]byte("one call"))
	refreshHash := sha256.Sum256([]byte("refresh token"))
	for _, code := range [][32]byte{twoCalls, oneCall} {
		must(t, g.CreateAuthorizationCode(ctx, storage.NewAuthorizationCode{CodeHash: code, ClientID: "c", Grant: secretGrant, ExpiresAt: codeExpiry}))
		_, err := g.RedeemAuthorizationCode(ctx, storage.AuthorizationCodeRedemption{CodeHash: code, ClientID: "c"})
		must(t, err)
	}
	must(t, g.RecordIssuedAccessToken(ctx, twoCalls, "access-key", access))
	must(t, g.RecordIssuedRefreshToken(ctx, twoCalls, refreshHash, refresh))
	must(t, g.RecordIssuedTokens(ctx, oneCall, "access-key", access, refreshHash, refresh))

	want, got := readIssued(t, p, twoCalls), readIssued(t, p, oneCall)
	if got.accessKey != want.accessKey || string(got.refreshHash) != string(want.refreshHash) || got.sweepAfter != want.sweepAfter {
		t.Fatalf("RecordIssuedTokens left %+v, the two calls %+v", got, want)
	}
	for _, code := range [][32]byte{twoCalls, oneCall} {
		_, err := g.RedeemAuthorizationCode(ctx, storage.AuthorizationCodeRedemption{CodeHash: code, ClientID: "c"})
		var reused *storage.AuthorizationCodeAlreadyRedeemedError
		if !errors.As(err, &reused) || reused.IssuedAccessTokenKey != "access-key" || reused.IssuedRefreshTokenHash == nil || *reused.IssuedRefreshTokenHash != refreshHash {
			t.Fatalf("reuse after recording = %v (%+v), want both tokens reported", err, reused)
		}
	}
}

// RecordIssuedTokens refuses what RecordIssuedAccessToken refuses — an
// unknown code, an access-token key no row can hold — recording
// nothing, refusing the key without wrapping ErrStoreUnavailable.
func TestRecordIssuedTokensRefusals(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		ctx := context.Background()
		p := newPlace(t, dialect)
		g := batchingGrants(t, p.migrated())
		later := time.Now().Add(time.Hour)
		code := sha256.Sum256([]byte("code"))
		if err := g.RecordIssuedTokens(ctx, code, "at", later, code, later); !errors.Is(err, sqlstore.ErrNotFound) {
			t.Errorf("RecordIssuedTokens(unknown code) = %v, want ErrNotFound", err)
		}
		must(t, g.CreateAuthorizationCode(ctx, storage.NewAuthorizationCode{CodeHash: code, ClientID: "c", Grant: secretGrant, ExpiresAt: later}))
		before := readIssued(t, p, code)
		for _, key := range []string{"a\x00b", "\xff"} {
			if err := g.RecordIssuedTokens(ctx, code, key, later, code, later); err == nil || errors.Is(err, storage.ErrStoreUnavailable) {
				t.Errorf("RecordIssuedTokens(key %q) = %v, want a refusal", key, err)
			}
		}
		if after := readIssued(t, p, code); after.accessKey.Valid || after.refreshHash != nil || after.sweepAfter != before.sweepAfter {
			t.Errorf("a refused RecordIssuedTokens left %+v, want the row as it was (%+v)", after, before)
		}
	})
}

// IsAnyRevoked and RecordIssuedTokens report a database they can't
// use as storage.ErrStoreUnavailable.
func TestBatchedCallsReportOutages(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		ctx := context.Background()
		p := newPlace(t, dialect)
		p.prefix = "never_migrated_" + p.prefix
		d, _ := p.open()
		code := sha256.Sum256([]byte("code"))
		if _, err := batchingRevocation(t, d).IsAnyRevoked(ctx, []string{"a", "b"}); !errors.Is(err, storage.ErrStoreUnavailable) {
			t.Errorf("IsAnyRevoked on missing tables = %v, want ErrStoreUnavailable", err)
		}
		if err := batchingGrants(t, d).RecordIssuedTokens(ctx, code, "at", time.Now(), code, time.Now()); !errors.Is(err, storage.ErrStoreUnavailable) || errors.Is(err, sqlstore.ErrNotFound) {
			t.Errorf("RecordIssuedTokens on missing tables = %v, want ErrStoreUnavailable only", err)
		}
	})
}

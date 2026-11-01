package sqlstore_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/sqlstore"
	"github.com/idfoundry/fapigo/storage"
)

// sealedFixture is a DB with a Sealer and one of each sealed record,
// writeOneOfEach's and a refresh token (client "o"), plus a second CIBA request (client
// "o2") and a second pushed request ("r2").
type sealedFixture struct {
	p      *place
	d      *sqlstore.DB
	db     *sql.DB
	sealer sqlstore.Sealer
}

func newSealedFixture(t *testing.T, dialect sqlstore.Dialect) sealedFixture {
	t.Helper()
	f := sealedFixture{p: newPlace(t, dialect), sealer: testSealer(t)}
	f.d = f.p.migratedWith(sqlstore.Options{Sealer: f.sealer})
	_, f.db = f.p.open()
	writeOneOfEach(t, f.d)
	createRefreshToken(t, f.d, "o")
	ctx := context.Background()
	other := cibaRequest("o2", "poll")
	other.ClientID = "o"
	must(t, f.d.Backchannel().CreateBackchannelAuthentication(ctx, other))
	must(t, f.d.Transactions().CreatePAR(ctx, storage.NewPARRecord{Reference: "r2", ClientID: "o", Request: secretGrant, ExpiresAt: time.Now().Add(time.Hour)}))
	return f
}

// exec runs query on f's database.
func (f sealedFixture) exec(t *testing.T, query string, args ...any) {
	t.Helper()
	rawExec(t, f.p, f.db, query, args...)
}

// table is name with f's prefix.
func (f sealedFixture) table(name string) string { return f.p.prefix + name }

// A database writer without the key can't change what a sealed record
// means by changing a column it's bound to but doesn't hold: its expiry
// (a token that never expires), a CIBA request's handle (approving
// another request), delivery mode or interval, or the pushed request
// an interaction consumes. The read is refused as unreadable.
func TestSealedRecordsAreBoundToTheirImmutableColumns(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		ctx := context.Background()
		far := int64(1) << 62
		o := sha256.Sum256([]byte("o"))
		for name, tc := range map[string]struct {
			tamper func(t *testing.T, f sealedFixture)
			read   func(f sealedFixture) error
		}{
			"access token expiry": {
				func(t *testing.T, f sealedFixture) {
					f.exec(t, "UPDATE "+f.table("access_tokens")+" SET expires_at = ?", far)
				},
				func(f sealedFixture) error {
					_, err := f.d.AccessTokens().LookupAccessToken(ctx, storage.AccessTokenLookup{TokenHash: o})
					return err
				},
			},
			"refresh token expiry": {
				func(t *testing.T, f sealedFixture) {
					f.exec(t, "UPDATE "+f.table("refresh_tokens")+" SET expires_at = ?", far)
				},
				func(f sealedFixture) error {
					_, err := f.d.Grants().RedeemRefreshToken(ctx, storage.RefreshTokenRedemption{TokenHash: sha256.Sum256([]byte("rt-o"))})
					return err
				},
			},
			"authorization code expiry": {
				func(t *testing.T, f sealedFixture) {
					f.exec(t, "UPDATE "+f.table("authorization_codes")+" SET expires_at = ?", far)
				},
				func(f sealedFixture) error {
					_, err := f.d.Grants().RedeemAuthorizationCode(ctx, storage.AuthorizationCodeRedemption{CodeHash: o})
					return err
				},
			},
			"pushed request expiry": {
				func(t *testing.T, f sealedFixture) {
					f.exec(t, "UPDATE "+f.table("par_requests")+" SET expires_at = ? WHERE reference = 'r2'", far)
				},
				func(f sealedFixture) error {
					_, err := f.d.Transactions().BeginAuthorization(ctx, storage.BeginAuthorizationTransaction{Reference: "r2", Handle: "h2", HandleExpiresAt: time.Now().Add(time.Minute), Now: time.Now()})
					return err
				},
			},
			"interaction expiry": {
				func(t *testing.T, f sealedFixture) {
					f.exec(t, "UPDATE "+f.table("interactions")+" SET expires_at = ?", far)
				},
				func(f sealedFixture) error { return completeInteraction(f.d, "h") },
			},
			"interaction reference": {
				func(t *testing.T, f sealedFixture) {
					f.exec(t, "UPDATE "+f.table("interactions")+" SET reference = 'r2'")
				},
				func(f sealedFixture) error { return completeInteraction(f.d, "h") },
			},
			"session expiry": {
				func(t *testing.T, f sealedFixture) {
					f.exec(t, "UPDATE "+f.table("client_sessions")+" SET expires_at = ?", far)
				},
				func(f sealedFixture) error {
					_, err := f.d.Sessions().Consume(ctx, storage.SessionConsumption{State: "o"})
					return err
				},
			},
			"CIBA handles swapped": {
				func(t *testing.T, f sealedFixture) { swapCIBAHandles(t, f) },
				func(f sealedFixture) error {
					_, err := f.d.Backchannel().LookupBackchannelAuthentication(ctx, o)
					return err
				},
			},
			"CIBA expiry": {
				func(t *testing.T, f sealedFixture) {
					f.exec(t, "UPDATE "+f.table("backchannel_authentications")+" SET expires_at = ?", far)
				},
				func(f sealedFixture) error { return pollCIBA(f.d, o) },
			},
			"CIBA delivery mode": {
				func(t *testing.T, f sealedFixture) {
					f.exec(t, "UPDATE "+f.table("backchannel_authentications")+" SET delivery_mode = 'ping'")
				},
				func(f sealedFixture) error {
					_, err := f.d.Backchannel().DecideBackchannelAuthentication(ctx, storage.DecideBackchannelAuthentication{HandleHash: o, Status: storage.BackchannelAuthenticationDenied})
					return err
				},
			},
			"CIBA poll interval": {
				func(t *testing.T, f sealedFixture) {
					f.exec(t, "UPDATE "+f.table("backchannel_authentications")+" SET poll_interval = 5000000000")
				},
				func(f sealedFixture) error { return pollCIBA(f.d, o) },
			},
		} {
			t.Run(name, func(t *testing.T) {
				f := newSealedFixture(t, dialect)
				tc.tamper(t, f)
				wantUnreadable(t, name, tc.read(f))
			})
		}
	})
}

// completeInteraction completes handle on d.
func completeInteraction(d *sqlstore.DB, handle string) error {
	_, err := d.Transactions().CompleteAuthorization(context.Background(), storage.CompleteAuthorizationTransaction{Handle: handle})
	return err
}

// pollCIBA polls the request keyed by the digest hash on d, now.
func pollCIBA(d *sqlstore.DB, hash [32]byte) error {
	_, err := d.Backchannel().PollBackchannelAuthentication(context.Background(), storage.PollBackchannelAuthentication{AuthReqIDHash: hash, Now: time.Now()})
	return err
}

// swapCIBAHandles swaps the handle_hash of f's two CIBA requests.
func swapCIBAHandles(t *testing.T, f sealedFixture) {
	t.Helper()
	o, o2 := sha256.Sum256([]byte("o")), cibaRequest("o2", "poll").HandleHash
	tmp := sha256.Sum256([]byte("tmp"))
	table := f.table("backchannel_authentications")
	f.exec(t, "UPDATE "+table+" SET handle_hash = ? WHERE handle_hash = ?", tmp[:], o[:])
	f.exec(t, "UPDATE "+table+" SET handle_hash = ? WHERE handle_hash = ?", o[:], o2[:])
	f.exec(t, "UPDATE "+table+" SET handle_hash = ? WHERE handle_hash = ?", o2[:], tmp[:])
}

// v1AdditionalData is sqlstore v0.2's additional data for a blob of
// table's column, in the row keyed by key, of client clientID's, under
// prefix.
func v1AdditionalData(prefix, table, column, key, clientID string) []byte {
	ad := []byte("fapigo sqlstore record v1")
	for _, part := range []string{prefix, table, column, key, clientID} {
		ad = binary.BigEndian.AppendUint32(ad, uint32(len(part))) //nolint:gosec // short test strings
		ad = append(ad, part...)
	}
	return ad
}

// A blob sealed by sqlstore v0.2 (format byte 2, v1 additional data)
// still opens, without the newer binding to its row's expiry, and
// SealRecords re-seals it in the current format, after which that
// binding holds.
func TestV1SealedRecordsOpenAndAreResealed(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		ctx := context.Background()
		f := newSealedFixture(t, dialect)
		hash := createRefreshToken(t, f.d, "a")
		v1, err := f.sealer.Seal(secretGrant, v1AdditionalData(f.p.prefix, "refresh_tokens", "record", string(hash[:]), "a"))
		must(t, err)
		f.exec(t, "UPDATE "+f.table("refresh_tokens")+" SET record = ?, expires_at = ? WHERE client_id = 'a'", append([]byte{2}, v1...), int64(1)<<62)
		redeem := func() error {
			_, err := f.d.Grants().RedeemRefreshToken(ctx, storage.RefreshTokenRedemption{TokenHash: hash})
			return err
		}
		must(t, redeem()) // a v1 blob doesn't bind its expiry

		n, err := f.d.SealRecords(ctx)
		if err != nil || n != 1 {
			t.Fatalf("SealRecords = %d, %v, want 1 (the v1 blob), nil", n, err)
		}
		if stored := rawColumn(t, f.p, f.db, "refresh_tokens", "record", "a"); stored[0] != 3 {
			t.Fatalf("record after SealRecords = %q, want it sealed in the current format", stored)
		}
		must(t, redeem())
		f.exec(t, "UPDATE "+f.table("refresh_tokens")+" SET expires_at = ? WHERE client_id = 'a'", int64(1)<<61)
		wantUnreadable(t, "RedeemRefreshToken(re-sealed, expiry changed)", redeem())
	})
}

// SealRecords stops with an error at a v1 blob its Sealer can't open,
// rather than re-sealing or skipping it.
func TestSealRecordsRefusesUnopenableV1Blob(t *testing.T) {
	ctx := context.Background()
	f := newSealedFixture(t, sqlstore.SQLite)
	hash := createRefreshToken(t, f.d, "a")
	v1, err := testSealer(t).Seal(secretGrant, v1AdditionalData(f.p.prefix, "refresh_tokens", "record", string(hash[:]), "a"))
	must(t, err)
	f.exec(t, "UPDATE "+f.table("refresh_tokens")+" SET record = ? WHERE client_id = 'a'", append([]byte{2}, v1...))
	_, err = f.d.SealRecords(ctx)
	wantUnreadable(t, "SealRecords(a v1 blob under another key)", err)
}

// On SQLite, a record stored with the TEXT storage class (by hand, or
// an import) in a BLOB column is sealed too, rather than read again
// forever because its compare-and-swap never matches.
func TestSealRecordsSealsSQLiteTextValues(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	p := newPlace(t, sqlstore.SQLite)
	d := p.migratedWith(sqlstore.Options{Sealer: testSealer(t), ReadUnsealed: true})
	_, db := p.open()
	rawExec(t, p, db, "INSERT INTO "+p.prefix+"par_requests (reference, client_id, request, expires_at, sweep_after) VALUES ('t', 'c', CAST('{\"v\":1}' AS TEXT), ?, ?)", int64(1)<<62, int64(1)<<62)
	n, err := d.SealRecords(ctx)
	if err != nil || n != 1 {
		t.Fatalf("SealRecords = %d, %v, want 1, nil", n, err)
	}
	got, err := d.Transactions().BeginAuthorization(ctx, storage.BeginAuthorizationTransaction{Reference: "t", Handle: "h", HandleExpiresAt: time.Now().Add(time.Minute), Now: time.Now()})
	if err != nil || string(got.Request) != `{"v":1}` {
		t.Fatalf("BeginAuthorization after SealRecords = %s, %v", got.Request, err)
	}
}

// SealRecords gives up, with an error, on rows it reads again and again
// but can't seal, rather than running until its context ends.
func TestSealRecordsStopsWithoutProgress(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	p := newPlace(t, sqlstore.SQLite)
	plain := p.migrated()
	_, db := p.open()
	createRefreshToken(t, plain, "a")
	// Every UPDATE of the row is silently skipped: its compare-and-swap
	// never takes effect.
	rawExec(t, p, db, "CREATE TRIGGER "+p.prefix+"stuck BEFORE UPDATE ON "+p.prefix+"refresh_tokens BEGIN SELECT RAISE(IGNORE); END")
	d := p.migratedWith(sqlstore.Options{Sealer: testSealer(t), ReadUnsealed: true})
	_, err := d.SealRecords(ctx)
	if err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("SealRecords on a row it can't seal = %v, want an error before its deadline", err)
	}
}

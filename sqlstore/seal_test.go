package sqlstore_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/sqlstore"
	"github.com/idfoundry/fapigo/storage"
)

// testSealer is an AESGCMSealer under a fresh random key.
func testSealer(t *testing.T) sqlstore.Sealer {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	s, err := sqlstore.AESGCMSealer(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// secretGrant is a grant whose secret must never reach the database in
// the clear once sealed.
var secretGrant = json.RawMessage(`{"sub":"user-secret-7f3a"}`)

// rawExec runs query, with ? placeholders, on db as p's dialect needs.
func rawExec(t *testing.T, p *place, db *sql.DB, query string, args ...any) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), placeholders(p, query), args...); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
}

// rawColumn reads column of the row of table whose client_id is
// clientID.
func rawColumn(t *testing.T, p *place, db *sql.DB, table, column, clientID string) []byte {
	t.Helper()
	var out []byte
	query := placeholders(p, "SELECT "+column+" FROM "+p.prefix+table+" WHERE client_id = ?")
	if err := db.QueryRowContext(context.Background(), query, clientID).Scan(&out); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return out
}

// placeholders numbers query's ? placeholders for PostgreSQL.
func placeholders(p *place, query string) string {
	if p.dialect != sqlstore.Postgres {
		return query
	}
	var b strings.Builder
	n := 0
	for _, c := range query {
		if c == '?' {
			n++
			b.WriteString("$" + strconv.Itoa(n))
			continue
		}
		b.WriteRune(c)
	}
	return b.String()
}

// createRefreshToken stores a refresh token of secretGrant's for
// clientID through d, returning its digest.
func createRefreshToken(t *testing.T, d *sqlstore.DB, clientID string) [32]byte {
	t.Helper()
	hash := sha256.Sum256([]byte("rt-" + clientID))
	must(t, d.Grants().CreateRefreshToken(context.Background(), storage.NewRefreshToken{
		TokenHash: hash, ClientID: fapi.ClientID(clientID), Grant: secretGrant, ExpiresAt: time.Now().Add(time.Hour),
	}))
	return hash
}

// wantUnreadable fails the test unless err is ErrRecordFormat, as an
// outage.
func wantUnreadable(t *testing.T, what string, err error) {
	t.Helper()
	if !errors.Is(err, sqlstore.ErrRecordFormat) || !errors.Is(err, storage.ErrStoreUnavailable) {
		t.Fatalf("%s = %v, want ErrRecordFormat wrapping storage.ErrStoreUnavailable", what, err)
	}
}

// A sealed record isn't in the database in the clear, and reads back.
func TestSealedRecordsAreNotInTheClear(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		p := newPlace(t, dialect)
		d := p.migratedWith(sqlstore.Options{Sealer: testSealer(t)})
		_, db := p.open()
		hash := createRefreshToken(t, d, "a")
		stored := rawColumn(t, p, db, "refresh_tokens", "record", "a")
		if len(stored) == 0 || stored[0] != 2 || bytes.Contains(stored, []byte("user-secret")) {
			t.Fatalf("stored record = %q, want it sealed (starting with byte 2), without the grant in the clear", stored)
		}
		got, err := d.Grants().RedeemRefreshToken(context.Background(), storage.RefreshTokenRedemption{TokenHash: hash})
		if err != nil || !bytes.Equal(got.Grant, secretGrant) {
			t.Fatalf("RedeemRefreshToken = %s, %v, want the grant back", got.Grant, err)
		}
	})
}

// A sealed blob is bound to its row: moved to another row (another key,
// another client, another table or another TablePrefix), altered, or
// opened under another key, it's refused.
func TestSealedRecordsAreBoundToTheirRow(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		ctx := context.Background()
		sealer := testSealer(t)
		p := newPlace(t, dialect)
		d := p.migratedWith(sqlstore.Options{Sealer: sealer})
		_, db := p.open()
		a, b := createRefreshToken(t, d, "a"), createRefreshToken(t, d, "b")
		redeem := func(d *sqlstore.DB, hash [32]byte) error {
			_, err := d.Grants().RedeemRefreshToken(ctx, storage.RefreshTokenRedemption{TokenHash: hash})
			return err
		}

		// Another row's blob.
		rawExec(t, p, db, "UPDATE "+p.prefix+"refresh_tokens SET record = ? WHERE client_id = 'b'", rawColumn(t, p, db, "refresh_tokens", "record", "a"))
		wantUnreadable(t, "RedeemRefreshToken(a blob moved from another row)", redeem(d, b))

		// Another client's row: the client_id column changed.
		rawExec(t, p, db, "UPDATE "+p.prefix+"refresh_tokens SET client_id = 'c' WHERE client_id = 'a'")
		wantUnreadable(t, "RedeemRefreshToken(a row moved to another client)", redeem(d, a))
		rawExec(t, p, db, "UPDATE "+p.prefix+"refresh_tokens SET client_id = 'a' WHERE client_id = 'c'")
		must(t, redeem(d, a))

		// Another table: an authorization code with the same digest and client.
		rawExec(t, p, db, "INSERT INTO "+p.prefix+"authorization_codes (code_hash, client_id, record, expires_at, sweep_after) VALUES (?, 'a', ?, 0, 0)",
			a[:], rawColumn(t, p, db, "refresh_tokens", "record", "a"))
		_, err := d.Grants().RedeemAuthorizationCode(ctx, storage.AuthorizationCodeRedemption{CodeHash: a})
		wantUnreadable(t, "RedeemAuthorizationCode(a refresh token's blob)", err)

		// Altered.
		stored := rawColumn(t, p, db, "refresh_tokens", "record", "a")
		stored[len(stored)-1] ^= 1
		rawExec(t, p, db, "UPDATE "+p.prefix+"refresh_tokens SET record = ? WHERE client_id = 'a'", stored)
		wantUnreadable(t, "RedeemRefreshToken(an altered blob)", redeem(d, a))

		// Another key.
		c := createRefreshToken(t, d, "c")
		wantUnreadable(t, "RedeemRefreshToken(under another key)", redeem(p.migratedWith(sqlstore.Options{Sealer: testSealer(t)}), c))

		// Another TablePrefix, under the same key.
		other := newPlace(t, dialect)
		other.path = p.path
		otherDB := other.migratedWith(sqlstore.Options{Sealer: sealer})
		_, odb := other.open()
		rawExec(t, other, odb, "INSERT INTO "+other.prefix+"refresh_tokens (token_hash, client_id, record, expires_at, sweep_after) VALUES (?, 'c', ?, 0, 0)",
			c[:], rawColumn(t, p, db, "refresh_tokens", "record", "c"))
		wantUnreadable(t, "RedeemRefreshToken(a blob from another TablePrefix)", redeem(otherDB, c))
	})
}

// Records written before a Sealer was set are refused by a DB with one,
// read with ReadUnsealed, and sealed in place by SealRecords, after
// which the DB reads them without ReadUnsealed. A DB without a Sealer
// refuses a sealed record.
func TestUnsealedRecordsMigration(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		ctx := context.Background()
		sealer := testSealer(t)
		p := newPlace(t, dialect)
		plain := p.migrated()
		_, db := p.open()
		hash := createRefreshToken(t, plain, "a")
		writeOneOfEach(t, plain)
		redeem := func(d *sqlstore.DB) error {
			_, err := d.Grants().RedeemRefreshToken(ctx, storage.RefreshTokenRedemption{TokenHash: hash})
			return err
		}

		sealed := p.migratedWith(sqlstore.Options{Sealer: sealer})
		wantUnreadable(t, "RedeemRefreshToken(unsealed, by a DB with a Sealer)", redeem(sealed))
		migrating := p.migratedWith(sqlstore.Options{Sealer: sealer, ReadUnsealed: true})
		must(t, redeem(migrating))

		n, err := migrating.SealRecords(ctx)
		// The refresh token, and writeOneOfEach's pushed request,
		// interaction, code, access token and CIBA record and decision.
		if err != nil || n != 7 {
			t.Fatalf("SealRecords = %d, %v, want 7, nil", n, err)
		}
		if n, err := migrating.SealRecords(ctx); err != nil || n != 0 {
			t.Fatalf("SealRecords again = %d, %v, want 0, nil", n, err)
		}
		must(t, redeem(sealed))
		checkOneOfEach(t, sealed)
		if stored := rawColumn(t, p, db, "refresh_tokens", "record", "a"); stored[0] != 2 {
			t.Fatalf("record after SealRecords = %q, want it sealed", stored)
		}
		wantUnreadable(t, "RedeemRefreshToken(sealed, by a DB without a Sealer)", redeem(plain))
	})
}

// writeOneOfEach writes one record of each sealed kind but the refresh
// token, for client "o".
func writeOneOfEach(t *testing.T, d *sqlstore.DB) {
	t.Helper()
	ctx := context.Background()
	later := time.Now().Add(time.Hour)
	must(t, d.Transactions().CreatePAR(ctx, storage.NewPARRecord{Reference: "r", ClientID: "o", Request: secretGrant, ExpiresAt: later}))
	_, err := d.Transactions().BeginAuthorization(ctx, storage.BeginAuthorizationTransaction{Reference: "r", Handle: "h", HandleExpiresAt: later, Now: time.Now()})
	must(t, err)
	must(t, d.Grants().CreateAuthorizationCode(ctx, storage.NewAuthorizationCode{CodeHash: sha256.Sum256([]byte("o")), ClientID: "o", Grant: secretGrant, ExpiresAt: later}))
	must(t, d.AccessTokens().CreateAccessToken(ctx, storage.NewAccessToken{TokenHash: sha256.Sum256([]byte("o")), ClientID: "o", Subject: "user-secret", ExpiresAt: later}))
	must(t, d.Backchannel().CreateBackchannelAuthentication(ctx, storage.NewBackchannelAuthentication{
		AuthReqIDHash: sha256.Sum256([]byte("o")), HandleHash: sha256.Sum256([]byte("o")), ClientID: "o", Request: secretGrant,
		DeliveryMode: "poll", ExpiresAt: later,
	}))
}

// checkOneOfEach reads back what writeOneOfEach wrote.
func checkOneOfEach(t *testing.T, d *sqlstore.DB) {
	t.Helper()
	ctx := context.Background()
	if got, err := d.Transactions().CompleteAuthorization(ctx, storage.CompleteAuthorizationTransaction{Handle: "h"}); err != nil || !bytes.Equal(got.Request, secretGrant) {
		t.Errorf("CompleteAuthorization = %s, %v", got.Request, err)
	}
	if got, err := d.Grants().RedeemAuthorizationCode(ctx, storage.AuthorizationCodeRedemption{CodeHash: sha256.Sum256([]byte("o"))}); err != nil || !bytes.Equal(got.Grant, secretGrant) {
		t.Errorf("RedeemAuthorizationCode = %s, %v", got.Grant, err)
	}
	if got, err := d.AccessTokens().LookupAccessToken(ctx, storage.AccessTokenLookup{TokenHash: sha256.Sum256([]byte("o"))}); err != nil || got.Subject != "user-secret" {
		t.Errorf("LookupAccessToken = %+v, %v", got, err)
	}
	if got, err := d.Backchannel().PollBackchannelAuthentication(ctx, storage.PollBackchannelAuthentication{AuthReqIDHash: sha256.Sum256([]byte("o")), Now: time.Now()}); err != nil || !bytes.Equal(got.Request, secretGrant) {
		t.Errorf("PollBackchannelAuthentication = %+v, %v", got, err)
	}
}

// failingSealer fails every seal and open.
type failingSealer struct{}

func (failingSealer) Seal([]byte, []byte) ([]byte, error) { return nil, errors.New("kms down") }
func (failingSealer) Open([]byte, []byte) ([]byte, error) { return nil, errors.New("kms down") }

// A Sealer's failure is an outage, and a write without a Sealer refuses
// a record that would read back as sealed.
func TestSealerFailures(t *testing.T) {
	ctx := context.Background()
	p := newPlace(t, sqlstore.SQLite)
	d := p.migratedWith(sqlstore.Options{Sealer: failingSealer{}})
	err := d.Grants().CreateRefreshToken(ctx, storage.NewRefreshToken{ClientID: "a", Grant: secretGrant, ExpiresAt: time.Now().Add(time.Hour)})
	if !errors.Is(err, storage.ErrStoreUnavailable) {
		t.Fatalf("CreateRefreshToken with a failing Sealer = %v, want storage.ErrStoreUnavailable", err)
	}
	if _, err := d.SealRecords(ctx); err != nil {
		t.Fatalf("SealRecords with nothing to seal = %v", err)
	}
	plain := p.migrated()
	createRefreshToken(t, plain, "a")
	if _, err := d.SealRecords(ctx); !errors.Is(err, storage.ErrStoreUnavailable) {
		t.Fatalf("SealRecords with a failing Sealer = %v, want storage.ErrStoreUnavailable", err)
	}
	err = plain.Grants().CreateRefreshToken(ctx, storage.NewRefreshToken{ClientID: "b", Grant: json.RawMessage("\x02{}"), ExpiresAt: time.Now()})
	if err == nil {
		t.Fatal("CreateRefreshToken(a grant starting with byte 2, no Sealer) = nil error, want a refusal")
	}
	if _, err := plain.SealRecords(ctx); err == nil {
		t.Fatal("SealRecords without a Sealer = nil error, want an error")
	}
	if _, err := sqlstore.New(&sql.DB{}, sqlstore.SQLite, sqlstore.Options{ReadUnsealed: true}); err == nil {
		t.Fatal("New(ReadUnsealed without a Sealer) = nil error, want an error")
	}
}

func TestAESGCMSealer(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33} {
		if _, err := sqlstore.AESGCMSealer(make([]byte, n)); err == nil {
			t.Errorf("AESGCMSealer(%d-byte key) = nil error, want an error", n)
		}
	}
	s := testSealer(t)
	a, err := s.Seal([]byte("x"), []byte("ad"))
	must(t, err)
	b, err := s.Seal([]byte("x"), []byte("ad"))
	must(t, err)
	if bytes.Equal(a, b) {
		t.Fatal("two seals of one plaintext are equal: the nonce isn't random")
	}
	if got, err := s.Open(a, []byte("ad")); err != nil || string(got) != "x" {
		t.Fatalf("Open = %q, %v", got, err)
	}
	for name, c := range map[string]struct{ sealed, ad []byte }{
		"other additional data": {a, []byte("other")},
		"too short":             {a[:5], []byte("ad")},
		"truncated":             {a[:len(a)-1], []byte("ad")},
	} {
		if _, err := s.Open(c.sealed, c.ad); err == nil {
			t.Errorf("Open(%s) = nil error, want an error", name)
		}
	}
}

// A record that opens but isn't one of this package's — not JSON,
// another version, an unknown value — is unreadable, as an outage.
func TestMalformedRecordsAreUnreadable(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		ctx := context.Background()
		p := newPlace(t, dialect)
		d := p.migrated()
		_, db := p.open()
		hash := sha256.Sum256([]byte("at"))
		must(t, d.AccessTokens().CreateAccessToken(ctx, storage.NewAccessToken{TokenHash: hash, ClientID: "c", ExpiresAt: time.Now().Add(time.Hour)}))
		r := cibaRequest("bad", "poll")
		must(t, d.Backchannel().CreateBackchannelAuthentication(ctx, r))
		goodRecord := rawColumn(t, p, db, "backchannel_authentications", "record", "c")
		for _, bad := range []string{`not json`, `{"v":2}`, `{"v":1,"sender_constrain":"bearer"}`} {
			rawExec(t, p, db, "UPDATE "+p.prefix+"access_tokens SET record = ?", []byte(bad))
			_, err := d.AccessTokens().LookupAccessToken(ctx, storage.AccessTokenLookup{TokenHash: hash})
			wantUnreadable(t, "LookupAccessToken("+bad+")", err)
			if strings.Contains(bad, "sender_constrain") {
				continue // a CIBA record has none
			}

			rawExec(t, p, db, "UPDATE "+p.prefix+"backchannel_authentications SET record = ?", []byte(bad))
			_, err = d.Backchannel().LookupBackchannelAuthentication(ctx, r.HandleHash)
			wantUnreadable(t, "LookupBackchannelAuthentication("+bad+")", err)
			rawExec(t, p, db, "UPDATE "+p.prefix+"backchannel_authentications SET record = ?", goodRecord)

			rawExec(t, p, db, "UPDATE "+p.prefix+"backchannel_authentications SET decision = ?", []byte(bad))
			_, err = d.Backchannel().PollBackchannelAuthentication(ctx, storage.PollBackchannelAuthentication{AuthReqIDHash: r.AuthReqIDHash, Now: time.Now()})
			wantUnreadable(t, "PollBackchannelAuthentication(decision "+bad+")", err)
		}
		// A decision on an unreadable record records nothing.
		rawExec(t, p, db, "UPDATE "+p.prefix+"backchannel_authentications SET record = ?", []byte(`{"v":2}`))
		_, err := d.Backchannel().DecideBackchannelAuthentication(ctx, storage.DecideBackchannelAuthentication{HandleHash: r.HandleHash, Status: storage.BackchannelAuthenticationDenied})
		wantUnreadable(t, "DecideBackchannelAuthentication(an unreadable record)", err)
		rawExec(t, p, db, "UPDATE "+p.prefix+"backchannel_authentications SET record = ?", goodRecord)
		_, err = d.Backchannel().DecideBackchannelAuthentication(ctx, storage.DecideBackchannelAuthentication{HandleHash: r.HandleHash, Status: storage.BackchannelAuthenticationDenied})
		must(t, err)
	})
}

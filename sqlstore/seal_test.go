package sqlstore_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
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
		if len(stored) == 0 || stored[0] != 3 || bytes.Contains(stored, []byte("user-secret")) {
			t.Fatalf("stored record = %q, want it sealed (starting with byte 3), without the grant in the clear", stored)
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
		// interaction, code, access token, CIBA record and decision, and
		// session.
		if err != nil || n != 8 {
			t.Fatalf("SealRecords = %d, %v, want 8, nil", n, err)
		}
		if n, err := migrating.SealRecords(ctx); err != nil || n != 0 {
			t.Fatalf("SealRecords again = %d, %v, want 0, nil", n, err)
		}
		must(t, redeem(sealed))
		checkOneOfEach(t, sealed)
		if stored := rawColumn(t, p, db, "refresh_tokens", "record", "a"); stored[0] != 3 {
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
	must(t, d.Sessions().Create(ctx, storage.NewSession{State: "o", Record: secretGrant, ExpiresAt: later}))
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
	if got, err := d.Sessions().Consume(ctx, storage.SessionConsumption{State: "o"}); err != nil || !bytes.Equal(got.Record, secretGrant) {
		t.Errorf("Consume = %s, %v", got.Record, err)
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
	err = plain.Grants().CreateRefreshToken(ctx, storage.NewRefreshToken{ClientID: "b", Grant: json.RawMessage("\x03{}"), ExpiresAt: time.Now()})
	if err == nil {
		t.Fatal("CreateRefreshToken(a grant starting with byte 3, no Sealer) = nil error, want a refusal")
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

// AESGCMSealer refuses a key that's certainly not random — a placeholder,
// a passphrase, or an encoded key not yet decoded — as FAPIgo's other
// sealers do, and RotatingSealer one key twice.
func TestAESGCMSealerRefusesWeakKeys(t *testing.T) {
	printable := bytes.Repeat([]byte("ab"), 16)
	printable[31] = '\n' // whitespace is text too
	for name, c := range map[string]struct {
		key  []byte
		want string
	}{
		"all zero":   {make([]byte, 32), "one byte repeated"},
		"all 0xff":   {bytes.Repeat([]byte{0xff}, 32), "one byte repeated"},
		"passphrase": {[]byte("correct horse battery staple!!!!"), "printable text"},
		"hex":        {[]byte("00112233445566778899aabbccddeeff"), "printable text"},
		"base64":     {[]byte("q83vEjRWeJCrze8SNFZ4kKvN7xI0VniQ")[:32], "printable text"},
		"text":       {printable, "printable text"},
	} {
		_, err := sqlstore.AESGCMSealer(c.key)
		if err == nil || !strings.Contains(err.Error(), c.want) || !strings.HasPrefix(err.Error(), "sqlstore: record sealer: ") {
			t.Errorf("AESGCMSealer(%s key) = %v, want an error saying %q", name, err, c.want)
		}
	}
	key := make([]byte, 32)
	_, err := rand.Read(key)
	must(t, err)
	key[0] = 0x80 // never all printable
	a, err := sqlstore.AESGCMSealer(key)
	must(t, err)
	b, err := sqlstore.AESGCMSealer(bytes.Clone(key))
	must(t, err)
	if _, err := sqlstore.RotatingSealer(a, testSealer(t), b); err == nil || !strings.Contains(err.Error(), "same key") {
		t.Errorf("RotatingSealer(one key twice) = %v, want an error", err)
	}
	if _, err := sqlstore.RotatingSealer(a, testSealer(t)); err != nil {
		t.Errorf("RotatingSealer(two keys) = %v", err)
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

// RotatingSealer seals with its current Sealer and opens with any of
// them, so records sealed under the previous key stay readable while new
// ones are sealed under the new key; a key it doesn't hold is refused.
func TestRotatingSealer(t *testing.T) {
	ctx := context.Background()
	oldKey, newKey := testSealer(t), testSealer(t)
	p := newPlace(t, sqlstore.SQLite)
	before := p.migratedWith(sqlstore.Options{Sealer: oldKey})
	oldHash := createRefreshToken(t, before, "old")

	rotating, err := sqlstore.RotatingSealer(newKey, oldKey)
	must(t, err)
	after := p.migratedWith(sqlstore.Options{Sealer: rotating})
	newHash := createRefreshToken(t, after, "new")
	for name, hash := range map[string][32]byte{"old": oldHash, "new": newHash} {
		if _, err := after.Grants().RedeemRefreshToken(ctx, storage.RefreshTokenRedemption{TokenHash: hash}); err != nil {
			t.Errorf("RedeemRefreshToken(%s key's record) through the rotating sealer = %v", name, err)
		}
	}
	// The new record is sealed under the new key alone.
	_, err = p.migratedWith(sqlstore.Options{Sealer: newKey}).Grants().RedeemRefreshToken(ctx, storage.RefreshTokenRedemption{TokenHash: newHash})
	must(t, err)
	_, err = before.Grants().RedeemRefreshToken(ctx, storage.RefreshTokenRedemption{TokenHash: newHash})
	wantUnreadable(t, "RedeemRefreshToken(new record, old key only)", err)

	other, err := sqlstore.RotatingSealer(testSealer(t), testSealer(t))
	must(t, err)
	_, err = p.migratedWith(sqlstore.Options{Sealer: other}).Grants().RedeemRefreshToken(ctx, storage.RefreshTokenRedemption{TokenHash: oldHash})
	wantUnreadable(t, "RedeemRefreshToken(under keys the rotating sealer doesn't hold)", err)

	if _, err := sqlstore.RotatingSealer(nil); err == nil {
		t.Error("RotatingSealer(nil) = nil error, want an error")
	}
	if _, err := sqlstore.RotatingSealer(newKey, nil); err == nil {
		t.Error("RotatingSealer(current, nil) = nil error, want an error")
	}
}

// SealRecords seals tables of more rows than one of its batches, every
// row once.
func TestSealRecordsPagesThroughTables(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		ctx := context.Background()
		p := newPlace(t, dialect)
		plain := p.migrated()
		const rows = 250
		for i := range rows {
			createRefreshToken(t, plain, strconv.Itoa(i))
			must(t, plain.Transactions().CreatePAR(ctx, storage.NewPARRecord{Reference: "ref-" + strconv.Itoa(i), ClientID: "c", Request: secretGrant, ExpiresAt: time.Now().Add(time.Hour)}))
		}
		sealer := testSealer(t)
		d := p.migratedWith(sqlstore.Options{Sealer: sealer, ReadUnsealed: true})
		if n, err := d.SealRecords(ctx); err != nil || n != 2*rows {
			t.Fatalf("SealRecords = %d, %v, want %d, nil", n, err, 2*rows)
		}
		if n, err := d.SealRecords(ctx); err != nil || n != 0 {
			t.Fatalf("SealRecords again = %d, %v, want 0, nil", n, err)
		}
		sealed := p.migratedWith(sqlstore.Options{Sealer: sealer})
		for _, i := range []int{0, rows / 2, rows - 1} {
			if _, err := sealed.Grants().RedeemRefreshToken(ctx, storage.RefreshTokenRedemption{TokenHash: sha256.Sum256([]byte("rt-" + strconv.Itoa(i)))}); err != nil {
				t.Fatalf("RedeemRefreshToken %d after SealRecords, without ReadUnsealed = %v", i, err)
			}
		}
	})
}

// blockingSealer is a Sealer whose Seal waits for release, after
// saying so on sealing.
type blockingSealer struct {
	sqlstore.Sealer
	sealing, release chan struct{}
}

func (s blockingSealer) Seal(plaintext, additionalData []byte) ([]byte, error) {
	s.sealing <- struct{}{}
	<-s.release
	return s.Sealer.Seal(plaintext, additionalData)
}

// A Create seals its record before it takes SQLite's write lock: a
// slow Sealer holds up no other write.
func TestCreateSealsOutsideTheWriteLock(t *testing.T) {
	sealer := blockingSealer{testSealer(t), make(chan struct{}), make(chan struct{})}
	d := newPlace(t, sqlstore.SQLite).migratedWith(sqlstore.Options{Sealer: sealer})
	ctx := context.Background()
	created := make(chan error, 1)
	go func() {
		created <- d.Grants().CreateRefreshToken(ctx, storage.NewRefreshToken{TokenHash: sha256.Sum256([]byte("slow")), ClientID: "c", Grant: secretGrant, ExpiresAt: time.Now().Add(time.Hour)})
	}()
	<-sealer.sealing
	wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err := d.Replay().UseOnce(wctx, storage.ReplayUse{Namespace: "n", Digest: sha256.Sum256([]byte("meanwhile")), ExpiresAt: time.Now().Add(time.Minute)})
	close(sealer.release)
	if err != nil {
		t.Fatalf("UseOnce while a Create is sealing = %v, want nil", err)
	}
	must(t, <-created)
}

// failingAfterSealer is a Sealer that seals n records, then fails.
type failingAfterSealer struct {
	sqlstore.Sealer
	n *int
}

func (s failingAfterSealer) Seal(plaintext, additionalData []byte) ([]byte, error) {
	if *s.n == 0 {
		return nil, errors.New("kms down")
	}
	*s.n--
	return s.Sealer.Seal(plaintext, additionalData)
}

// Every Create whose Sealer fails — for a CIBA request, at either of
// its two blobs — is an outage.
func TestCreateSealerFailures(t *testing.T) {
	ctx := context.Background()
	later := time.Now().Add(time.Hour)
	creates := map[string]func(d *sqlstore.DB) error{
		"CreatePAR": func(d *sqlstore.DB) error {
			return d.Transactions().CreatePAR(ctx, storage.NewPARRecord{Reference: "r", ClientID: "c", Request: secretGrant, ExpiresAt: later})
		},
		"CreateAuthorizationCode": func(d *sqlstore.DB) error {
			return d.Grants().CreateAuthorizationCode(ctx, storage.NewAuthorizationCode{ClientID: "c", Grant: secretGrant, ExpiresAt: later})
		},
		"CreateAccessToken": func(d *sqlstore.DB) error {
			return d.AccessTokens().CreateAccessToken(ctx, storage.NewAccessToken{ClientID: "c", ExpiresAt: later})
		},
		"CreateBackchannelAuthentication": func(d *sqlstore.DB) error {
			return d.Backchannel().CreateBackchannelAuthentication(ctx, cibaRequest("sealing", "poll"))
		},
		"Sessions.Create": func(d *sqlstore.DB) error {
			return d.Sessions().Create(ctx, storage.NewSession{State: "s", Record: secretGrant, ExpiresAt: later})
		},
	}
	for name, create := range creates {
		for _, sealed := range []int{0, 1} {
			if sealed == 1 && name != "CreateBackchannelAuthentication" {
				continue
			}
			t.Run(fmt.Sprintf("%s/after %d", name, sealed), func(t *testing.T) {
				n := sealed
				d := newPlace(t, sqlstore.SQLite).migratedWith(sqlstore.Options{Sealer: failingAfterSealer{testSealer(t), &n}})
				if err := create(d); !errors.Is(err, storage.ErrStoreUnavailable) {
					t.Fatalf("%s with a failing Sealer = %v, want storage.ErrStoreUnavailable", name, err)
				}
			})
		}
	}
}

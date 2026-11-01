package sqlstore

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"

	"github.com/idfoundry/fapigo/storage"
)

// Sealer seals and opens the record blobs a DB writes (Options.Sealer):
// an AEAD, such as AESGCMSealer, or a call to a key management service.
// Open must refuse sealed data altered in any way, or sealed with other
// additionalData: that's what binds each blob to its row. OID4VCgo's
// verifier.TransactionSealer (and its sqlstore.Sealer) is the same
// interface, so one sealer value can serve both.
type Sealer interface {
	Seal(plaintext, additionalData []byte) ([]byte, error)
	Open(sealed, additionalData []byte) ([]byte, error)
}

// AESGCMSealer is a Sealer that seals with AES-256-GCM under key (32
// bytes, from a cryptographically secure source, kept outside the
// database), with a random 96-bit nonce from crypto/rand for each seal.
//
// Random nonces bound how much one key may seal: NIST SP 800-38D
// (§8.3) allows at most 2^32 seals with random 96-bit nonces under one
// key, beyond which a repeated nonce — which would let anyone who can
// read and write the database forge sealed records — becomes too
// likely. A server seals a few records per authorization (the pushed
// request, the interaction's copy, the code, an opaque access token, a
// refresh token) and two per refresh, so a busy one can reach 2^32 in
// weeks: at 1,000 seals a second, in about seven weeks. Rotate the key
// well before then (say, at a quarter of the budget, or monthly at that
// rate), with RotatingSealer.
//
// Changing the key makes the blobs sealed under the previous one
// unreadable; to rotate it, seal with the new key and open with both,
// until the records sealed under the old one expire: RotatingSealer.
func AESGCMSealer(key []byte) (Sealer, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("sqlstore: record sealer: key is %d bytes, want 32 (AES-256)", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("sqlstore: record sealer: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("sqlstore: record sealer: %w", err)
	}
	return gcmSealer{aead}, nil
}

// RotatingSealer is a Sealer for rotating keys: it seals with current,
// and opens with current or, failing that, each of previous in turn.
// To rotate, make the new key current and the old one previous, deploy
// every instance with it, and drop the old key once every record it
// sealed has expired — the longest-lived are refresh tokens, so after
// the refresh token lifetime (plus the time to deploy). The sealed
// blobs' format is current's, unchanged, so the database needs nothing
// to switch to it, and a blob sealed under no key it holds is refused
// as before. Every open of an old record tries current first; with an
// AEAD such as AESGCMSealer, that failure is cheap.
func RotatingSealer(current Sealer, previous ...Sealer) (Sealer, error) {
	if current == nil || slices.Contains(previous, nil) {
		return nil, errors.New("sqlstore: rotating sealer: nil Sealer")
	}
	return rotatingSealer{append([]Sealer{current}, previous...)}, nil
}

type rotatingSealer struct{ sealers []Sealer }

func (s rotatingSealer) Seal(plaintext, additionalData []byte) ([]byte, error) {
	return s.sealers[0].Seal(plaintext, additionalData)
}

func (s rotatingSealer) Open(sealed, additionalData []byte) ([]byte, error) {
	var errs []error
	for _, sealer := range s.sealers {
		plain, err := sealer.Open(sealed, additionalData)
		if err == nil {
			return plain, nil
		}
		errs = append(errs, err)
	}
	return nil, errors.Join(errs...)
}

type gcmSealer struct{ aead cipher.AEAD }

func (s gcmSealer) Seal(plaintext, additionalData []byte) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return s.aead.Seal(nonce, nonce, plaintext, additionalData), nil
}

func (s gcmSealer) Open(sealed, additionalData []byte) ([]byte, error) {
	if len(sealed) < s.aead.NonceSize() {
		return nil, errors.New("sealed data is too short")
	}
	nonce, ciphertext := sealed[:s.aead.NonceSize()], sealed[s.aead.NonceSize():]
	return s.aead.Open(nil, nonce, ciphertext, additionalData)
}

// ErrRecordFormat is what a store returns, wrapped, for a record blob it
// can't read: sealed, by a DB without a Sealer; not sealed, by a DB
// whose Sealer requires it (Options.ReadUnsealed unset); sealed under
// another key, for another row, or altered. It always wraps
// storage.ErrStoreUnavailable too: it's the deployment's problem, not
// the client's.
var ErrRecordFormat = errors.New("sqlstore: unreadable record")

// recordSealed is the first byte of a blob sealed now; the rest is what
// the Sealer returned, for additional data in the v2 format (see
// blobRef.additionalData). recordSealedV1 is that of a blob sealed by
// sqlstore v0.2 and earlier, with v1 additional data, which a store
// still opens and SealRecords re-seals. An unsealed blob is the record
// as the server handed it (JSON, or empty), which no JSON document
// starts with.
const (
	recordSealedV1 byte = 2
	recordSealed   byte = 3
)

// blobRef names one record blob: the column of the row whose key is
// key, in table, holding a record of clientID's. A sealed blob is bound
// to all of it, to the DB's TablePrefix, and to the row's columns that
// change the record's meaning but never change once it's written: its
// expires_at, and any of bound's.
type blobRef struct {
	table, column string
	key           string // the row's primary key: text, or a digest's bytes
	clientID      string
	expires       int64    // the row's expires_at
	bound         []string // the table's other bound columns, in a fixed order (sealedColumn.bound)
}

// additionalData is ref's AEAD additional data under prefix for a blob
// of format (recordSealed or recordSealedV1): each part length-prefixed,
// so no two refs share it. The v1 format (sqlstore v0.2 and earlier)
// binds neither expires nor bound, so a database writer can change those
// columns of a v1 blob's row; SealRecords re-seals such blobs as v2.
func (ref blobRef) additionalData(prefix string, format byte) []byte {
	parts := []string{prefix, ref.table, ref.column, ref.key, ref.clientID}
	ad := []byte("fapigo sqlstore record v1")
	if format != recordSealedV1 {
		ad = []byte("fapigo sqlstore record v2")
		parts = append(parts, string(binary.BigEndian.AppendUint64(nil, uint64(ref.expires)))) //nolint:gosec // the bits, as they are
		parts = append(parts, ref.bound...)
	}
	for _, part := range parts {
		ad = binary.BigEndian.AppendUint32(ad, uint32(len(part))) //nolint:gosec // parts are far shorter than 4 GiB
		ad = append(ad, part...)
	}
	return ad
}

// isSealed reports whether stored, a record column's value, is sealed,
// in either format.
func isSealed(stored []byte) bool {
	return len(stored) > 0 && (stored[0] == recordSealed || stored[0] == recordSealedV1)
}

// seal is plaintext as ref's column value: sealed with d's Sealer, or
// as is without one. Its caller wraps its error, a Sealer's failure,
// with storage.ErrStoreUnavailable, as it does the database's.
func (d *DB) seal(ref blobRef, plaintext []byte) ([]byte, error) {
	if d.sealer == nil {
		if isSealed(plaintext) {
			return nil, fmt.Errorf("sqlstore: %s %s: an unsealed record can't start with byte %d", ref.table, ref.column, plaintext[0])
		}
		return blob(plaintext), nil
	}
	sealed, err := d.sealer.Seal(plaintext, ref.additionalData(d.prefix, recordSealed))
	if err != nil {
		return nil, fmt.Errorf("sqlstore: seal %s %s: %w", ref.table, ref.column, err)
	}
	return append([]byte{recordSealed}, sealed...), nil
}

// open is seal's inverse: the record in stored, ref's column value.
func (d *DB) open(ref blobRef, stored []byte) ([]byte, error) {
	sealed := isSealed(stored)
	switch {
	case sealed && d.sealer == nil:
		return nil, d.recordFormat(ref, "it is sealed, and the DB has no Sealer")
	case !sealed && d.sealer != nil && !d.readUnsealed:
		return nil, d.recordFormat(ref, "it isn't sealed, and the DB's Sealer requires it (see Options.ReadUnsealed)")
	case !sealed:
		return rawJSON(stored), nil
	}
	opened, err := d.sealer.Open(stored[1:], ref.additionalData(d.prefix, stored[0]))
	if err != nil {
		return nil, d.recordFormat(ref, "open: "+err.Error())
	}
	return rawJSON(opened), nil
}

// recordFormat is ErrRecordFormat for ref, for why.
func (d *DB) recordFormat(ref blobRef, why string) error {
	return fmt.Errorf("%w: %w: %s %s: %s", ErrRecordFormat, storage.ErrStoreUnavailable, ref.table, ref.column, why)
}

// decodeRecord decodes plain, one of this package's own versioned JSON
// records, into v, whose version field is version: it must be want.
func decodeRecord(plain []byte, v any, version *int, want int) error {
	if err := json.Unmarshal(plain, v); err != nil {
		return fmt.Errorf("%w: %w: %w", ErrRecordFormat, storage.ErrStoreUnavailable, err)
	}
	if *version != want {
		return fmt.Errorf("%w: %w: record version %d, want %d", ErrRecordFormat, storage.ErrStoreUnavailable, *version, want)
	}
	return nil
}

// The tables and columns of the record blobs a Sealer seals.
const (
	backchannelTable = "backchannel_authentications"
	recordColumn     = "record"
	requestColumn    = "request"
	decisionColumn   = "decision"
)

// interactionRef names the request column of the interaction handle,
// client clientID's, begun from the pushed request reference and
// expiring at expires: reference is bound too, since completing the
// interaction consumes it.
func interactionRef(handle, clientID, reference string, expires int64) blobRef {
	return blobRef{"interactions", requestColumn, handle, clientID, expires, []string{reference}}
}

// sealedColumn is one column of record blobs a Sealer seals: the
// column, its table, the table's key column, the client ID each blob is
// also bound to — the client_id column, or the empty string for the
// client sessions' table, which has none — and the table's other bound
// columns (blobRef.bound), besides expires_at, which every one has.
type sealedColumn struct {
	table, keyColumn, column string
	clientID                 string // an SQL expression
	textKey                  bool
	bound                    []boundColumn
}

// boundColumn is a column of blobRef.bound: its name, and whether it's
// an integer, bound as its decimal digits.
type boundColumn struct {
	name    string
	integer bool
}

// The bound columns of interactions (interactionRef) and CIBA requests
// (backchannelBound).
var (
	interactionBound        = []boundColumn{{"reference", false}}
	backchannelBoundColumns = []boundColumn{{"handle_hash", false}, {"delivery_mode", false}, {"poll_interval", true}}
)

// sealedColumns are the record blobs a Sealer seals.
var sealedColumns = []sealedColumn{
	{"par_requests", "reference", requestColumn, "client_id", true, nil},
	{"interactions", "handle", requestColumn, "client_id", true, interactionBound},
	{"authorization_codes", "code_hash", recordColumn, "client_id", false, nil},
	{"refresh_tokens", "token_hash", recordColumn, "client_id", false, nil},
	{"access_tokens", "token_hash", recordColumn, "client_id", false, nil},
	{backchannelTable, "auth_req_id_hash", recordColumn, "client_id", false, backchannelBoundColumns},
	{backchannelTable, "auth_req_id_hash", decisionColumn, "client_id", false, backchannelBoundColumns},
	{sessionsTable, "state", recordColumn, "''", true, nil},
}

// sealStallLimit is how many batches in a row SealRecords lets read
// rows without sealing any before it gives up: a row whose
// compare-and-swap can never match would otherwise be read again
// forever.
const sealStallLimit = 3

// SealRecords seals, in place, every record blob that isn't sealed yet
// — those written before Options.Sealer was set — and re-seals every
// blob sealed by sqlstore v0.2 or earlier, whose additional data binds
// less (see the package documentation's Sealing section), and returns
// how many it sealed. It's the way to start sealing an existing
// database:
//
//  1. deploy every instance with Sealer set and ReadUnsealed true, so
//     they read the rows written before and seal every row they write;
//  2. run SealRecords once;
//  3. deploy again with ReadUnsealed false, so that from then on a blob
//     that isn't sealed is refused rather than trusted.
//
// and, run once after upgrading from sqlstore v0.2, the way to bind
// the rows sealed before to their expiry too, without waiting for them
// to expire. It trusts what it finds: a blob a database writer planted
// before it ran, unsealed (or, for a v0.2 blob, its row's expiry
// changed), is sealed as if the server had written it, so run it on a
// database whose contents you trust.
//
// It seals a batch of rows per transaction, each blob only if it hasn't
// changed since it was read, so it's safe to run while the server is
// serving. It requires a Sealer, which must open the v0.2 blobs. It
// stops with an error if a v0.2 blob doesn't open, or if it keeps
// reading rows it can't seal.
func (d *DB) SealRecords(ctx context.Context) (int64, error) {
	if d.sealer == nil {
		return 0, errors.New("sqlstore: seal records: the DB has no Sealer")
	}
	var total int64
	for _, c := range sealedColumns {
		n, err := d.sealColumn(ctx, c)
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// sealColumn is SealRecords for c.
func (d *DB) sealColumn(ctx context.Context, c sealedColumn) (int64, error) {
	var total int64
	for stalls := 0; ; {
		var sealed, read int64
		err := d.write(ctx, func(q querier) error {
			var err error
			sealed, read, err = d.sealBatch(ctx, q, c)
			return err
		})
		if err != nil {
			return total, unavailable("seal records in "+c.table, err)
		}
		total += sealed
		switch {
		case read == 0:
			return total, nil
		case sealed > 0:
			stalls = 0
		default:
			if stalls++; stalls >= sealStallLimit {
				return total, fmt.Errorf("sqlstore: seal records in %s: %d rows read but none sealed, %d batches in a row: their %s changes as it's sealed, or can't be compared", c.table, read, stalls, c.column)
			}
		}
	}
}

// unsealedRow is a row SealRecords is sealing.
type unsealedRow struct {
	key      []byte
	clientID string
	stored   []byte
	expires  int64
	bound    []string
}

// ref is the blobRef of r's value of c.
func (r unsealedRow) ref(c sealedColumn) blobRef {
	return blobRef{c.table, c.column, string(r.key), r.clientID, r.expires, r.bound}
}

// sealBatch reads up to 100 of c's values on q that aren't sealed in
// the current format and seals each that hasn't changed since,
// returning how many it sealed and how many it read: none once none is
// left. One that changed is read again by the next batch, if it's still
// not sealed.
func (d *DB) sealBatch(ctx context.Context, q querier, c sealedColumn) (sealed, read int64, err error) {
	rows, err := d.unsealedRows(ctx, q, c)
	if err != nil {
		return 0, 0, err
	}
	n, err := d.sealRows(ctx, q, c, rows)
	return n, int64(len(rows)), err
}

// sealRows seals rows' values of c on q — opening a v1 one first —
// each only if it hasn't changed since it was read, returning how many
// it sealed.
func (d *DB) sealRows(ctx context.Context, q querier, c sealedColumn, rows []unsealedRow) (int64, error) {
	var total int64
	for _, r := range rows {
		ref := r.ref(c)
		plain := r.stored
		if len(r.stored) > 0 && r.stored[0] == recordSealedV1 {
			var err error
			if plain, err = d.sealer.Open(r.stored[1:], ref.additionalData(d.prefix, recordSealedV1)); err != nil {
				return 0, d.recordFormat(ref, "open a v1 sealed record: "+err.Error())
			}
		}
		sealed, err := d.seal(ref, plain)
		if err != nil {
			return 0, err
		}
		var key any = r.key
		if c.textKey {
			key = string(r.key)
		}
		res, err := q.ExecContext(ctx, d.q("UPDATE {"+c.table+"} SET "+c.column+" = ? WHERE "+c.keyColumn+" = ? AND "+d.asBlob(c.column)+" = ?"), sealed, key, r.stored)
		if err != nil {
			return 0, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return 0, err
		}
		total += n
	}
	return total, nil
}

// asBlob is the SQL expression reading column, a binary one, as bytes.
// SQLite keeps a value's own storage class in a BLOB column, so one
// written as TEXT (by hand, or by an import) is read and compared as
// bytes only cast; PostgreSQL's bytea is bytes already.
func (d *DB) asBlob(column string) string {
	if d.dialect == SQLite {
		return "CAST(" + column + " AS BLOB)"
	}
	return column
}

// unsealedRows reads up to 100 of c's table's rows whose column isn't
// sealed in the current format.
func (d *DB) unsealedRows(ctx context.Context, q querier, c sealedColumn) ([]unsealedRow, error) {
	columns := c.keyColumn + ", " + c.clientID + ", " + d.asBlob(c.column) + ", expires_at"
	for _, b := range c.bound {
		columns += ", " + b.name
	}
	rows, err := q.QueryContext(ctx, d.q("SELECT "+columns+" FROM {"+c.table+"} WHERE substr("+d.asBlob(c.column)+", 1, 1) <> ? LIMIT 100"), []byte{recordSealed})
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []unsealedRow
	for rows.Next() {
		r, err := scanUnsealedRow(rows, c)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// scanUnsealedRow scans one of unsealedRows' rows of c.
func scanUnsealedRow(rows *sql.Rows, c sealedColumn) (unsealedRow, error) {
	var r unsealedRow
	texts := make([][]byte, len(c.bound))
	ints := make([]int64, len(c.bound))
	dest := []any{&r.key, &r.clientID, &r.stored, &r.expires}
	for i, b := range c.bound {
		if b.integer {
			dest = append(dest, &ints[i])
		} else {
			dest = append(dest, &texts[i])
		}
	}
	if err := rows.Scan(dest...); err != nil {
		return unsealedRow{}, err
	}
	for i, b := range c.bound {
		if b.integer {
			r.bound = append(r.bound, strconv.FormatInt(ints[i], 10))
		} else {
			r.bound = append(r.bound, string(texts[i]))
		}
	}
	return r, nil
}

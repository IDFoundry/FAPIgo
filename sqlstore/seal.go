package sqlstore

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

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
// database), with a random nonce from crypto/rand for each seal.
// Changing the key makes the blobs sealed under the previous one
// unreadable; to rotate it, open with both until those records expire,
// with a Sealer of your own.
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

// recordSealed is the first byte of a sealed blob; the rest is what the
// Sealer returned. An unsealed blob is the record as the server handed
// it (JSON, or empty), which no JSON document starts with.
const recordSealed byte = 2

// blobRef names one record blob: the column of the row whose key is
// key, in table, holding a record of clientID's. A sealed blob is bound
// to all of it, and to the DB's TablePrefix.
type blobRef struct {
	table, column string
	key           string // the row's primary key: text, or a digest's bytes
	clientID      string
}

// additionalData is ref's AEAD additional data under prefix: each part
// length-prefixed, so no two refs share it.
func (ref blobRef) additionalData(prefix string) []byte {
	ad := []byte("fapigo sqlstore record v1")
	for _, part := range []string{prefix, ref.table, ref.column, ref.key, ref.clientID} {
		ad = binary.BigEndian.AppendUint32(ad, uint32(len(part))) //nolint:gosec // parts are far shorter than 4 GiB
		ad = append(ad, part...)
	}
	return ad
}

// seal is plaintext as ref's column value: sealed with d's Sealer, or
// as is without one. Its caller wraps its error, a Sealer's failure,
// with storage.ErrStoreUnavailable, as it does the database's.
func (d *DB) seal(ref blobRef, plaintext []byte) ([]byte, error) {
	if d.sealer == nil {
		if len(plaintext) > 0 && plaintext[0] == recordSealed {
			return nil, fmt.Errorf("sqlstore: %s %s: an unsealed record can't start with byte %d", ref.table, ref.column, recordSealed)
		}
		return blob(plaintext), nil
	}
	sealed, err := d.sealer.Seal(plaintext, ref.additionalData(d.prefix))
	if err != nil {
		return nil, fmt.Errorf("sqlstore: seal %s %s: %w", ref.table, ref.column, err)
	}
	return append([]byte{recordSealed}, sealed...), nil
}

// open is seal's inverse: the record in stored, ref's column value.
func (d *DB) open(ref blobRef, stored []byte) ([]byte, error) {
	sealed := len(stored) > 0 && stored[0] == recordSealed
	switch {
	case sealed && d.sealer == nil:
		return nil, d.recordFormat(ref, "it is sealed, and the DB has no Sealer")
	case !sealed && d.sealer != nil && !d.readUnsealed:
		return nil, d.recordFormat(ref, "it isn't sealed, and the DB's Sealer requires it (see Options.ReadUnsealed)")
	case !sealed:
		return rawJSON(stored), nil
	}
	opened, err := d.sealer.Open(stored[1:], ref.additionalData(d.prefix))
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

// sealedColumn is one column of record blobs a Sealer seals: the
// column, its table, the table's key column, and the client ID each
// blob is also bound to — the client_id column, or the empty string
// for the client sessions' table, which has none.
type sealedColumn struct {
	table, keyColumn, column string
	clientID                 string // an SQL expression
	textKey                  bool
}

// sealedColumns are the record blobs a Sealer seals.
var sealedColumns = []sealedColumn{
	{"par_requests", "reference", requestColumn, "client_id", true},
	{"interactions", "handle", requestColumn, "client_id", true},
	{"authorization_codes", "code_hash", recordColumn, "client_id", false},
	{"refresh_tokens", "token_hash", recordColumn, "client_id", false},
	{"access_tokens", "token_hash", recordColumn, "client_id", false},
	{backchannelTable, "auth_req_id_hash", recordColumn, "client_id", false},
	{backchannelTable, "auth_req_id_hash", decisionColumn, "client_id", false},
	{sessionsTable, "state", recordColumn, "''", true},
}

// SealRecords seals, in place, every record blob that isn't sealed yet
// — those written before Options.Sealer was set — and returns how many
// it sealed. It's the way to start sealing an existing database:
//
//  1. deploy every instance with Sealer set and ReadUnsealed true, so
//     they read the rows written before and seal every row they write;
//  2. run SealRecords once;
//  3. deploy again with ReadUnsealed false, so that from then on a blob
//     that isn't sealed is refused rather than trusted.
//
// It seals a batch of rows per transaction, each blob only if it hasn't
// changed since it was read, so it's safe to run while the server is
// serving. It requires a Sealer.
func (d *DB) SealRecords(ctx context.Context) (int64, error) {
	if d.sealer == nil {
		return 0, errors.New("sqlstore: seal records: the DB has no Sealer")
	}
	var total int64
	for _, c := range sealedColumns {
		for {
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
			if read == 0 {
				break
			}
		}
	}
	return total, nil
}

// unsealedRow is a row SealRecords is sealing.
type unsealedRow struct {
	key      []byte
	clientID string
	stored   []byte
}

// sealBatch reads up to 100 of c's unsealed values on q and seals each
// that hasn't changed since, returning how many it sealed and how many
// it read: none once none is left. One that changed is read again by
// the next batch, if it's still unsealed.
func (d *DB) sealBatch(ctx context.Context, q querier, c sealedColumn) (sealed, read int64, err error) {
	rows, err := d.unsealedRows(ctx, q, c)
	if err != nil {
		return 0, 0, err
	}
	n, err := d.sealRows(ctx, q, c, rows)
	return n, int64(len(rows)), err
}

// sealRows seals rows' values of c on q, each only if it hasn't changed
// since it was read, returning how many it sealed.
func (d *DB) sealRows(ctx context.Context, q querier, c sealedColumn, rows []unsealedRow) (int64, error) {
	var total int64
	for _, r := range rows {
		sealed, err := d.seal(blobRef{table: c.table, column: c.column, key: string(r.key), clientID: r.clientID}, r.stored)
		if err != nil {
			return 0, err
		}
		var key any = r.key
		if c.textKey {
			key = string(r.key)
		}
		res, err := q.ExecContext(ctx, d.q("UPDATE {"+c.table+"} SET "+c.column+" = ? WHERE "+c.keyColumn+" = ? AND "+c.column+" = ?"), sealed, key, r.stored)
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

// unsealedRows reads up to 100 of c's table's rows whose column isn't
// sealed.
func (d *DB) unsealedRows(ctx context.Context, q querier, c sealedColumn) ([]unsealedRow, error) {
	rows, err := q.QueryContext(ctx, d.q("SELECT "+c.keyColumn+", "+c.clientID+", "+c.column+" FROM {"+c.table+"} WHERE substr("+c.column+", 1, 1) <> ? LIMIT 100"), []byte{recordSealed})
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []unsealedRow
	for rows.Next() {
		var r unsealedRow
		if err := rows.Scan(&r.key, &r.clientID, &r.stored); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

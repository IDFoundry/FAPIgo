package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"slices"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/storage"
)

// GrantStore is a storage.GrantStore: server.Dependencies.Grants. It
// keeps authorization codes and refresh tokens in separate tables, each
// keyed by the digest the server hands it, never the value itself. It's
// a storage.GrantRefreshTokenRevoker too: it indexes each refresh token
// by its grant keys, so server.Server.RevokeGrant, and the reuse of an
// authorization code, revoke the grant's refresh tokens in the store.
type GrantStore struct{ d *DB }

// Every store DB hands out for server.Dependencies.Grants revokes a
// grant's refresh tokens: Grants itself, and BatchingGrants, whose store
// keeps GrantStore's refresh token methods, so the one it promotes
// revokes what they store.
var (
	_ storage.GrantRefreshTokenRevoker = (*GrantStore)(nil)
	_ storage.GrantRefreshTokenRevoker = batchingGrantStore{}
)

// Grants returns d's storage.GrantStore.
func (d *DB) Grants() *GrantStore { return &GrantStore{d} }

// CreateAuthorizationCode implements storage.GrantStore.
func (s *GrantStore) CreateAuthorizationCode(ctx context.Context, code storage.NewAuthorizationCode) error {
	if !validTextKey(string(code.ClientID)) {
		return errors.New("sqlstore: create authorization code: client_id isn't valid UTF-8 without NUL")
	}
	expires := nanos(code.ExpiresAt)
	record, err := s.d.seal(blobRef{"authorization_codes", recordColumn, string(code.CodeHash[:]), string(code.ClientID), expires, nil}, code.Grant)
	if err != nil {
		return unavailable("create authorization code", err)
	}
	err = s.d.writeOne(ctx, func(q querier) error {
		_, err := q.ExecContext(ctx, s.d.q("INSERT INTO {authorization_codes} (code_hash, client_id, record, expires_at, sweep_after) VALUES (?, ?, ?, ?, ?)"),
			code.CodeHash[:], string(code.ClientID), record, expires, expires)
		return err
	})
	if err != nil {
		return unavailable("create authorization code", err)
	}
	return nil
}

// RedeemAuthorizationCode implements storage.GrantStore: one UPDATE …
// RETURNING marks the code redeemed only if it wasn't already (and, with
// redemption.ClientID set, only if it was issued to that client), so of
// concurrent redemptions exactly one wins. When it matches nothing, the
// row is read to say why: unknown, issued to another client (left
// unredeemed), or already redeemed
// (*storage.AuthorizationCodeAlreadyRedeemedError).
func (s *GrantStore) RedeemAuthorizationCode(ctx context.Context, redemption storage.AuthorizationCodeRedemption) (storage.RedeemedAuthorizationCode, error) {
	if !validTextKey(string(redemption.ClientID)) {
		// No code was issued to it: refuse without redeeming.
		return storage.RedeemedAuthorizationCode{}, s.whyNotRedeemed(ctx, redemption.CodeHash)
	}
	var clientID string
	var record []byte
	var expires int64
	err := s.d.writeOne(ctx, func(q querier) error {
		return q.QueryRowContext(ctx, s.d.q("UPDATE {authorization_codes} SET redeemed = 1, sweep_after = "+redeemedSweep+" WHERE code_hash = ? AND redeemed = 0 AND (? = '' OR client_id = ?) RETURNING client_id, record, expires_at"),
			redeemedSweepArgs(redemption.CodeHash[:], string(redemption.ClientID), string(redemption.ClientID))...).Scan(&clientID, &record, &expires)
	})
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return storage.RedeemedAuthorizationCode{}, s.whyNotRedeemed(ctx, redemption.CodeHash)
	case err != nil:
		return storage.RedeemedAuthorizationCode{}, unavailable("redeem authorization code", err)
	}
	grant, err := s.d.open(blobRef{"authorization_codes", recordColumn, string(redemption.CodeHash[:]), clientID, expires, nil}, record)
	if err != nil {
		return storage.RedeemedAuthorizationCode{}, fmt.Errorf("sqlstore: redeem authorization code: %w", err)
	}
	return storage.RedeemedAuthorizationCode{ClientID: fapi.ClientID(clientID), Grant: grant, ExpiresAt: timeOf(expires)}, nil
}

// RedeemedCodeRetention is how long past its expiry Sweep keeps an
// authorization code once it's redeemed, at least. The server records
// the tokens a redemption issues (RecordIssuedAccessToken,
// RecordIssuedRefreshToken) only after it has issued them, and those
// calls keep the code until the tokens expire; until then, this keeps a
// code redeemed in the last moments before its expiry from being swept
// in between, which would make its reuse look like an unknown code
// rather than a reuse, and so revoke nothing (RFC 6749 §4.1.2).
const RedeemedCodeRetention = time.Hour

// redeemedSweep is the SQL expression that keeps a redeemed code's
// sweep_after at least RedeemedCodeRetention past its expires_at (or
// as it is, for an expiry so late the sum would overflow), with
// redeemedSweepArgs' arguments.
const redeemedSweep = "CASE WHEN expires_at > ? THEN sweep_after WHEN sweep_after < expires_at + ? THEN expires_at + ? ELSE sweep_after END"

// redeemedSweepArgs is redeemedSweep's arguments, followed by rest.
func redeemedSweepArgs(rest ...any) []any {
	retention := int64(RedeemedCodeRetention)
	return append([]any{int64(math.MaxInt64) - retention, retention, retention}, rest...)
}

// whyNotRedeemed is RedeemAuthorizationCode's error for a code its
// UPDATE didn't redeem.
func (s *GrantStore) whyNotRedeemed(ctx context.Context, codeHash [32]byte) error {
	var clientID string
	var redeemed int
	var accessKey sql.NullString
	var refreshHash []byte
	err := s.d.queryRow(ctx, "SELECT client_id, redeemed, issued_access_token_key, issued_refresh_token_hash FROM {authorization_codes} WHERE code_hash = ?",
		codeHash[:]).Scan(&clientID, &redeemed, &accessKey, &refreshHash)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("sqlstore: redeem authorization code: %w", notFound("authorization code"))
	case err != nil:
		return unavailable("redeem authorization code", err)
	case redeemed == 0:
		return errors.New("sqlstore: redeem authorization code: the code was issued to another client")
	}
	reused := &storage.AuthorizationCodeAlreadyRedeemedError{IssuedAccessTokenKey: accessKey.String, ClientID: fapi.ClientID(clientID)}
	if len(refreshHash) == 32 {
		h := [32]byte(refreshHash)
		reused.IssuedRefreshTokenHash = &h
	}
	return reused
}

// RecordIssuedAccessToken implements storage.GrantStore, keeping the
// code's row at least until the access token expires.
func (s *GrantStore) RecordIssuedAccessToken(ctx context.Context, codeHash [32]byte, key string, expiresAt time.Time) error {
	if !validTextKey(key) {
		return errors.New("sqlstore: record issued access token: key isn't valid UTF-8 without NUL")
	}
	return s.recordIssued(ctx, "access_token", "issued_access_token_key = ?", codeHash, nanos(expiresAt), key)
}

// RecordIssuedRefreshToken implements storage.GrantStore, keeping the
// code's row at least until the refresh token expires.
func (s *GrantStore) RecordIssuedRefreshToken(ctx context.Context, codeHash [32]byte, refreshTokenHash [32]byte, expiresAt time.Time) error {
	return s.recordIssued(ctx, "refresh_token", "issued_refresh_token_hash = ?", codeHash, nanos(expiresAt), refreshTokenHash[:])
}

// BatchingGrants returns d's GrantStore as a storage.GrantStore that is
// also a storage.IssuedTokensRecorder, for server.Dependencies.Grants:
//
//	Grants: db.BatchingGrants(),
//
// Its RecordIssuedTokens is RecordIssuedAccessToken and
// RecordIssuedRefreshToken together, in one UPDATE of the code's row:
// both recorded or neither, and the row kept at least until the later
// of the two tokens expires, as the two calls in turn would keep it.
// The server discovers it by type assertion and makes one call where it
// would otherwise make those two. It's otherwise d.Grants(), a
// storage.StoreAssurance with its Capabilities and a
// storage.GrantRefreshTokenRevoker.
//
// It's a method of DB, rather than of GrantStore, so that a wrapper of
// a deployment's own that embeds *GrantStore and overrides
// RecordIssuedAccessToken or RecordIssuedRefreshToken inherits neither
// RecordIssuedTokens nor a way to get this store: the server would call
// either past the overrides. A wrapper embedding what BatchingGrants
// returns, a storage.GrantStore, isn't an IssuedTokensRecorder unless
// it implements RecordIssuedTokens itself.
func (d *DB) BatchingGrants() storage.GrantStore { return batchingGrantStore{d.Grants()} }

// batchingGrantStore is DB.BatchingGrants' store.
type batchingGrantStore struct{ *GrantStore }

// RecordIssuedTokens implements storage.IssuedTokensRecorder — see
// DB.BatchingGrants.
func (b batchingGrantStore) RecordIssuedTokens(ctx context.Context, codeHash [32]byte, accessTokenKey string, accessExpiresAt time.Time, refreshTokenHash [32]byte, refreshExpiresAt time.Time) error {
	return b.recordIssuedTokens(ctx, codeHash, accessTokenKey, accessExpiresAt, refreshTokenHash, refreshExpiresAt)
}

// recordIssuedTokens is batchingGrantStore's RecordIssuedTokens.
func (s *GrantStore) recordIssuedTokens(ctx context.Context, codeHash [32]byte, accessTokenKey string, accessExpiresAt time.Time, refreshTokenHash [32]byte, refreshExpiresAt time.Time) error {
	if !validTextKey(accessTokenKey) {
		return errors.New("sqlstore: record issued tokens: access token key isn't valid UTF-8 without NUL")
	}
	until := max(nanos(accessExpiresAt), nanos(refreshExpiresAt))
	return s.recordIssued(ctx, "tokens", "issued_access_token_key = ?, issued_refresh_token_hash = ?", codeHash, until, accessTokenKey, refreshTokenHash[:])
}

// recordIssued sets the columns of set (assignments of values), the
// record of tokens issued as codeHash was redeemed, keeping the row's
// sweep_after at least until (Unix nanoseconds).
func (s *GrantStore) recordIssued(ctx context.Context, what, set string, codeHash [32]byte, until int64, values ...any) error {
	args := slices.Concat(values, []any{until, until, codeHash[:]})
	var n int64
	err := s.d.writeOne(ctx, func(q querier) error {
		res, err := q.ExecContext(ctx, s.d.q("UPDATE {authorization_codes} SET "+set+", sweep_after = "+laterSweep+" WHERE code_hash = ?"), args...)
		if err != nil {
			return err
		}
		n, err = res.RowsAffected()
		return err
	})
	switch {
	case err != nil:
		return unavailable("record issued "+what, err)
	case n == 0:
		return fmt.Errorf("sqlstore: record issued %s: %w", what, notFound("authorization code"))
	}
	return nil
}

// opCreateRefreshToken names CreateRefreshToken in its errors.
const opCreateRefreshToken = "create refresh token"

// CreateRefreshToken implements storage.GrantStore. It also indexes the
// token by each of its GrantKeys, for RevokeGrantRefreshTokens, in the
// transaction that stores it, so a failure stores neither the token nor
// any of its index rows. It refuses a grant key that isn't 1 to 64
// base64url characters, which every key the server derives is (see
// storage.NewRefreshToken.GrantKeys), and stores a key given twice once.
func (s *GrantStore) CreateRefreshToken(ctx context.Context, token storage.NewRefreshToken) error {
	if !validTextKey(string(token.ClientID)) {
		return errors.New("sqlstore: create refresh token: client_id isn't valid UTF-8 without NUL")
	}
	keys, err := grantKeysOf(token.GrantKeys)
	if err != nil {
		return err
	}
	expires := nanos(token.ExpiresAt)
	record, err := s.d.seal(blobRef{"refresh_tokens", recordColumn, string(token.TokenHash[:]), string(token.ClientID), expires, nil}, token.Grant)
	if err != nil {
		return unavailable(opCreateRefreshToken, err)
	}
	write := s.d.writeOne
	if len(keys) > 0 {
		write = s.d.write // the token and its index rows: more than one statement
	}
	err = write(ctx, func(q querier) error { return s.insertRefreshToken(ctx, q, token, record, keys) })
	if err != nil {
		return unavailable(opCreateRefreshToken, err)
	}
	return nil
}

// insertRefreshToken inserts, on q, token's row, its record as it's
// stored, and an index row for each of keys.
func (s *GrantStore) insertRefreshToken(ctx context.Context, q querier, token storage.NewRefreshToken, record []byte, keys []string) error {
	expires := nanos(token.ExpiresAt)
	if _, err := q.ExecContext(ctx, s.d.q("INSERT INTO {refresh_tokens} (token_hash, client_id, record, expires_at, sweep_after) VALUES (?, ?, ?, ?, ?)"),
		token.TokenHash[:], string(token.ClientID), record, expires, expires); err != nil {
		return err
	}
	for _, key := range keys {
		if _, err := q.ExecContext(ctx, s.d.q("INSERT INTO {refresh_token_grants} (grant_key, token_hash, sweep_after) VALUES (?, ?, ?)"),
			key, token.TokenHash[:], expires); err != nil {
			return err
		}
	}
	return nil
}

// maxGrantKeyBytes is the longest grant key a refresh token is indexed
// by (storage.NewRefreshToken.GrantKeys): the server's are base64url
// SHA-256 digests, 43 bytes.
const maxGrantKeyBytes = 64

// validGrantKey reports whether key can be a grant key a refresh token
// is indexed by: 1 to maxGrantKeyBytes characters of the base64url
// alphabet, as storage.NewRefreshToken.GrantKeys documents, and so a
// text key every dialect can hold (validTextKey).
func validGrantKey(key string) bool {
	if key == "" || len(key) > maxGrantKeyBytes {
		return false
	}
	for i := range len(key) {
		if !isBase64URLByte(key[i]) {
			return false
		}
	}
	return true
}

// isBase64URLByte reports whether c is in the base64url alphabet (RFC
// 4648 §5), padding aside.
func isBase64URLByte(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_'
}

// grantKeysOf is keys, a new refresh token's GrantKeys, each once, or
// an error if one isn't a valid grant key (validGrantKey).
func grantKeysOf(keys []string) ([]string, error) {
	if slices.ContainsFunc(keys, func(key string) bool { return !validGrantKey(key) }) {
		return nil, fmt.Errorf("sqlstore: create refresh token: a grant key isn't 1 to %d base64url characters", maxGrantKeyBytes)
	}
	return slices.Compact(slices.Sorted(slices.Values(keys))), nil
}

// RevokeGrantRefreshTokens implements storage.GrantRefreshTokenRevoker:
// one DELETE … RETURNING, in a transaction, of every refresh token
// CreateRefreshToken indexed by grantKey, which revokes all of them or,
// failing, none, and returns their hashes. A grant key no token can have
// (see CreateRefreshToken) has none, which isn't an error. A token whose
// CreateRefreshToken commits after the DELETE has read the index is left
// for the next call, as the interface allows. The index rows stay until
// Sweep removes them, with their tokens' expiry: a later call finds
// those tokens gone, and reports nothing for them. It deletes no
// tombstone (see RevokeRefreshToken): one stays until Sweep removes it.
//
// A wrapper of a deployment's own that embeds *GrantStore and overrides
// CreateRefreshToken, RedeemRefreshToken or RevokeRefreshToken inherits
// this method, which the server then calls past those overrides (see
// storage.GrantRefreshTokenRevoker). Unlike the batch methods
// DB.BatchingGrants keeps off this store, that can only leave a token the
// wrapper keeps apart from this store unrevoked, never let one the
// wrapper revoked be redeemed: the server checks the grant's revocation
// record on every redemption, whatever this method revoked.
func (s *GrantStore) RevokeGrantRefreshTokens(ctx context.Context, grantKey string) ([][32]byte, error) {
	if !validGrantKey(grantKey) {
		return nil, nil
	}
	var revoked [][32]byte
	err := s.d.write(ctx, func(q querier) error {
		var err error
		revoked, err = s.deleteIndexedRefreshTokens(ctx, q, grantKey)
		return err
	})
	if err != nil {
		return nil, unavailable("revoke grant refresh tokens", err)
	}
	return revoked, nil
}

// deleteIndexedRefreshTokens deletes, on q, every refresh token indexed
// by grantKey, returning their hashes. A row whose token_hash isn't a
// digest's 32 bytes, as no token CreateRefreshToken stored has, is
// deleted but not reported.
func (s *GrantStore) deleteIndexedRefreshTokens(ctx context.Context, q querier, grantKey string) ([][32]byte, error) {
	rows, err := q.QueryContext(ctx, s.d.q("DELETE FROM {refresh_tokens} WHERE revoked = 0 AND token_hash IN (SELECT token_hash FROM {refresh_token_grants} WHERE grant_key = ?) RETURNING token_hash"), grantKey)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var revoked [][32]byte
	for rows.Next() {
		var hash []byte
		if err := rows.Scan(&hash); err != nil {
			return nil, err
		}
		if len(hash) == 32 {
			revoked = append(revoked, [32]byte(hash))
		}
	}
	return revoked, rows.Err()
}

// RedeemRefreshToken implements storage.GrantStore. Not single-use (see
// the interface): it only reads the token, which stays until it's
// revoked or swept. A tombstone (see RevokeRefreshToken) is as unknown
// as no row, and never opened as a record.
func (s *GrantStore) RedeemRefreshToken(ctx context.Context, redemption storage.RefreshTokenRedemption) (storage.RedeemedRefreshToken, error) {
	var clientID string
	var record []byte
	var expires int64
	err := s.d.queryRow(ctx, "SELECT client_id, record, expires_at FROM {refresh_tokens} WHERE token_hash = ? AND revoked = 0",
		redemption.TokenHash[:]).Scan(&clientID, &record, &expires)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return storage.RedeemedRefreshToken{}, fmt.Errorf("sqlstore: redeem refresh token: %w", notFound("refresh token (unknown or revoked)"))
	case err != nil:
		return storage.RedeemedRefreshToken{}, unavailable("redeem refresh token", err)
	}
	grant, err := s.d.open(blobRef{"refresh_tokens", recordColumn, string(redemption.TokenHash[:]), clientID, expires, nil}, record)
	if err != nil {
		return storage.RedeemedRefreshToken{}, fmt.Errorf("sqlstore: redeem refresh token: %w", err)
	}
	return storage.RedeemedRefreshToken{ClientID: fapi.ClientID(clientID), Grant: grant, ExpiresAt: timeOf(expires)}, nil
}

// RevokeRefreshToken implements storage.GrantStore. It deletes the
// token, so a later RedeemRefreshToken finds none, or, finding none to
// delete, writes a tombstone under its hash: a row marked revoked, which
// RedeemRefreshToken treats as unknown, and which keeps
// CreateRefreshToken from storing a token under the hash while it
// lasts. So a token revoked before it's stored — by a revocation that
// read its hash from the server's grant registry while the token's
// issuance was still in flight — isn't redeemable either: its
// CreateRefreshToken fails while the tombstone lasts
// (tombstoneLifetime), which outlasts any issuance in flight. The
// tombstone is written by an upsert on the table's primary key, so a
// token stored between the DELETE and it becomes the tombstone, and one
// whose transaction is storing it meanwhile is waited for and then
// becomes it; on SQLite, whose writes are serialized, a token is stored
// before the DELETE, between the two, or not at all. Sweep removes a
// tombstone an hour after it's written (tombstoneLifetime). Revoking an
// unknown, or already revoked, token isn't an error.
func (s *GrantStore) RevokeRefreshToken(ctx context.Context, tokenHash [32]byte) error {
	var deleted int64
	err := s.d.writeOne(ctx, func(q querier) error {
		res, err := q.ExecContext(ctx, s.d.q("DELETE FROM {refresh_tokens} WHERE token_hash = ? AND revoked = 0"), tokenHash[:])
		if err != nil {
			return err
		}
		deleted, err = res.RowsAffected()
		return err
	})
	if err == nil && deleted == 0 {
		err = s.writeTombstone(ctx, tokenHash)
	}
	if err != nil {
		return unavailable("revoke refresh token", err)
	}
	return nil
}

// tombstoneLifetime is how long a tombstone RevokeRefreshToken writes
// lasts, by the instance's own clock, before Sweep removes it: longer
// than any CreateRefreshToken of its hash can still be in flight. The
// server stores a refresh token straight after recording its grant in
// the grant registry, the one place a revocation can read the token's
// hash from before it's stored (a client presents a token, and a code
// records one, only once it's stored). In between are only the store's
// own waits — for a pooled connection, for SQLite's write lock
// (Options.SQLiteBusyTimeout, ten seconds by default), for a row lock on
// PostgreSQL — and database/sql's immediate retry of a statement whose
// connection broke before it was sent: the server never retries the
// store. An hour covers those many times over, as RedeemedCodeRetention
// covers the server's recording of a redeemed code's tokens. An issuance
// slower still is caught by the server itself, which confirms the grant
// is still recorded once the token is stored, and revokes the token if
// it isn't.
const tombstoneLifetime = time.Hour

// tombstoneRecord is a tombstone's record: the byte a sealed record
// starts with (recordSealed) and nothing after it. No release of this
// package opens it, with a Sealer or without (a DB without one refuses
// a sealed record, and an AEAD opens nothing from no bytes), so one
// that doesn't know tombstones, v0.9 among them, answers a redemption
// of one as an unreadable record, an outage, never with a token; and
// SealRecords, which seals what doesn't start with that byte, leaves it
// alone.
var tombstoneRecord = []byte{recordSealed}

// writeTombstone writes a tombstone under tokenHash: one upsert, which
// turns a token stored under it into the tombstone too. Its client_id
// is empty, its record tombstoneRecord, its expires_at the earliest
// time a row can hold, and its sweep_after tombstoneLifetime from now.
func (s *GrantStore) writeTombstone(ctx context.Context, tokenHash [32]byte) error {
	until := nanos(time.Now().Add(tombstoneLifetime))
	return s.d.writeOne(ctx, func(q querier) error {
		_, err := q.ExecContext(ctx, s.d.q("INSERT INTO {refresh_tokens} (token_hash, client_id, record, expires_at, sweep_after, revoked) VALUES (?, '', ?, ?, ?, 1) ON CONFLICT (token_hash) DO UPDATE SET client_id = excluded.client_id, record = excluded.record, expires_at = excluded.expires_at, sweep_after = excluded.sweep_after, revoked = excluded.revoked"),
			tokenHash[:], tombstoneRecord, int64(math.MinInt64), until)
		return err
	})
}

// Capabilities implements storage.StoreAssurance — see the package
// documentation.
func (s *GrantStore) Capabilities() storage.Capabilities { return s.d.sealedCapabilities() }

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
// keyed by the digest the server hands it, never the value itself.
type GrantStore struct{ d *DB }

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

// RecordIssuedTokens is RecordIssuedAccessToken and
// RecordIssuedRefreshToken together, in one UPDATE of the code's row:
// both recorded or neither, and the row kept at least until the later
// of the two tokens expires, as the two calls in turn would keep it.
// The server discovers it by type assertion (fapigo's
// storage.IssuedTokensRecorder) and makes one call where it would
// otherwise make those two.
func (s *GrantStore) RecordIssuedTokens(ctx context.Context, codeHash [32]byte, accessTokenKey string, accessExpiresAt time.Time, refreshTokenHash [32]byte, refreshExpiresAt time.Time) error {
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

// CreateRefreshToken implements storage.GrantStore.
func (s *GrantStore) CreateRefreshToken(ctx context.Context, token storage.NewRefreshToken) error {
	if !validTextKey(string(token.ClientID)) {
		return errors.New("sqlstore: create refresh token: client_id isn't valid UTF-8 without NUL")
	}
	expires := nanos(token.ExpiresAt)
	record, err := s.d.seal(blobRef{"refresh_tokens", recordColumn, string(token.TokenHash[:]), string(token.ClientID), expires, nil}, token.Grant)
	if err != nil {
		return unavailable("create refresh token", err)
	}
	err = s.d.writeOne(ctx, func(q querier) error {
		_, err := q.ExecContext(ctx, s.d.q("INSERT INTO {refresh_tokens} (token_hash, client_id, record, expires_at, sweep_after) VALUES (?, ?, ?, ?, ?)"),
			token.TokenHash[:], string(token.ClientID), record, expires, expires)
		return err
	})
	if err != nil {
		return unavailable("create refresh token", err)
	}
	return nil
}

// RedeemRefreshToken implements storage.GrantStore. Not single-use (see
// the interface): it only reads the token, which stays until it's
// revoked or swept.
func (s *GrantStore) RedeemRefreshToken(ctx context.Context, redemption storage.RefreshTokenRedemption) (storage.RedeemedRefreshToken, error) {
	var clientID string
	var record []byte
	var expires int64
	err := s.d.queryRow(ctx, "SELECT client_id, record, expires_at FROM {refresh_tokens} WHERE token_hash = ?",
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

// RevokeRefreshToken implements storage.GrantStore by deleting the
// token, so a later RedeemRefreshToken finds none. Revoking an unknown
// (or already revoked) token is not an error: there is nothing left
// that could redeem it.
func (s *GrantStore) RevokeRefreshToken(ctx context.Context, tokenHash [32]byte) error {
	err := s.d.writeOne(ctx, func(q querier) error {
		_, err := q.ExecContext(ctx, s.d.q("DELETE FROM {refresh_tokens} WHERE token_hash = ?"), tokenHash[:])
		return err
	})
	if err != nil {
		return unavailable("revoke refresh token", err)
	}
	return nil
}

// Capabilities implements storage.StoreAssurance — see the package
// documentation.
func (s *GrantStore) Capabilities() storage.Capabilities { return s.d.sealedCapabilities() }

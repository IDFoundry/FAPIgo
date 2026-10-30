package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
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
	err := s.d.writeOne(ctx, func(q querier) error {
		record, err := s.d.seal(blobRef{"authorization_codes", recordColumn, string(code.CodeHash[:]), string(code.ClientID)}, code.Grant)
		if err != nil {
			return err
		}
		_, err = q.ExecContext(ctx, s.d.q("INSERT INTO {authorization_codes} (code_hash, client_id, record, expires_at, sweep_after) VALUES (?, ?, ?, ?, ?)"),
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
		return q.QueryRowContext(ctx, s.d.q("UPDATE {authorization_codes} SET redeemed = 1 WHERE code_hash = ? AND redeemed = 0 AND (? = '' OR client_id = ?) RETURNING client_id, record, expires_at"),
			redemption.CodeHash[:], string(redemption.ClientID), string(redemption.ClientID)).Scan(&clientID, &record, &expires)
	})
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return storage.RedeemedAuthorizationCode{}, s.whyNotRedeemed(ctx, redemption.CodeHash)
	case err != nil:
		return storage.RedeemedAuthorizationCode{}, unavailable("redeem authorization code", err)
	}
	grant, err := s.d.open(blobRef{"authorization_codes", recordColumn, string(redemption.CodeHash[:]), clientID}, record)
	if err != nil {
		return storage.RedeemedAuthorizationCode{}, fmt.Errorf("sqlstore: redeem authorization code: %w", err)
	}
	return storage.RedeemedAuthorizationCode{ClientID: fapi.ClientID(clientID), Grant: grant, ExpiresAt: timeOf(expires)}, nil
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
	return s.recordIssued(ctx, "access_token", "issued_access_token_key", codeHash, key, expiresAt)
}

// RecordIssuedRefreshToken implements storage.GrantStore, keeping the
// code's row at least until the refresh token expires.
func (s *GrantStore) RecordIssuedRefreshToken(ctx context.Context, codeHash [32]byte, refreshTokenHash [32]byte, expiresAt time.Time) error {
	return s.recordIssued(ctx, "refresh_token", "issued_refresh_token_hash", codeHash, refreshTokenHash[:], expiresAt)
}

// recordIssued sets column, the record of a token issued as codeHash
// was redeemed, to value.
func (s *GrantStore) recordIssued(ctx context.Context, what, column string, codeHash [32]byte, value any, expiresAt time.Time) error {
	until := nanos(expiresAt)
	var n int64
	err := s.d.writeOne(ctx, func(q querier) error {
		res, err := q.ExecContext(ctx, s.d.q("UPDATE {authorization_codes} SET "+column+" = ?, sweep_after = "+laterSweep+" WHERE code_hash = ?"),
			value, until, until, codeHash[:])
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
	err := s.d.writeOne(ctx, func(q querier) error {
		record, err := s.d.seal(blobRef{"refresh_tokens", recordColumn, string(token.TokenHash[:]), string(token.ClientID)}, token.Grant)
		if err != nil {
			return err
		}
		_, err = q.ExecContext(ctx, s.d.q("INSERT INTO {refresh_tokens} (token_hash, client_id, record, expires_at, sweep_after) VALUES (?, ?, ?, ?, ?)"),
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
	grant, err := s.d.open(blobRef{"refresh_tokens", recordColumn, string(redemption.TokenHash[:]), clientID}, record)
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

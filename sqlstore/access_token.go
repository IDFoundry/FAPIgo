package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/storage"
)

// AccessTokenStore is a storage.AccessTokenStore: the store of
// server.OpaqueAccessTokens (server.Dependencies.AccessTokens), and of
// a resource server's resource.OpaqueAccessTokens too. JWT access
// tokens need none.
type AccessTokenStore struct{ d *DB }

// AccessTokens returns d's storage.AccessTokenStore.
func (d *DB) AccessTokens() *AccessTokenStore { return &AccessTokenStore{d} }

// accessTokenRecordVersion is the version of accessTokenRecord's JSON.
const accessTokenRecordVersion = 1

// accessTokenRecord is an access token's record column: what
// LookupAccessToken returns, less the client_id and expires_at columns.
type accessTokenRecord struct {
	Version         int                        `json:"v"`
	Subject         string                     `json:"sub,omitempty"`
	Scope           []string                   `json:"scope,omitempty"`
	Thumbprint      string                     `json:"thumbprint,omitempty"`
	SenderConstrain string                     `json:"sender_constrain"`
	Claims          map[string]json.RawMessage `json:"claims,omitempty"`
}

// CreateAccessToken implements storage.AccessTokenStore.
func (s *AccessTokenStore) CreateAccessToken(ctx context.Context, tok storage.NewAccessToken) error {
	if !validTextKey(string(tok.ClientID)) {
		return errors.New("sqlstore: create access token: client_id isn't valid UTF-8 without NUL")
	}
	if !tok.SenderConstrain.IsValid() {
		return fmt.Errorf("sqlstore: create access token: unknown sender constrain %d", tok.SenderConstrain)
	}
	plain, err := json.Marshal(accessTokenRecord{
		Version: accessTokenRecordVersion, Subject: tok.Subject, Scope: tok.Scope,
		Thumbprint: tok.Thumbprint, SenderConstrain: tok.SenderConstrain.String(), Claims: tok.Claims,
	})
	if err != nil {
		return fmt.Errorf("sqlstore: create access token: %w", err)
	}
	expires := nanos(tok.ExpiresAt)
	err = s.d.writeOne(ctx, func(q querier) error {
		record, err := s.d.seal(blobRef{"access_tokens", recordColumn, string(tok.TokenHash[:]), string(tok.ClientID)}, plain)
		if err != nil {
			return err
		}
		_, err = q.ExecContext(ctx, s.d.q("INSERT INTO {access_tokens} (token_hash, client_id, record, expires_at, sweep_after) VALUES (?, ?, ?, ?, ?)"),
			tok.TokenHash[:], string(tok.ClientID), record, expires, expires)
		return err
	})
	if err != nil {
		return unavailable("create access token", err)
	}
	return nil
}

// LookupAccessToken implements storage.AccessTokenStore. It returns the
// token even once expired, until Sweep removes it: the caller compares
// ExpiresAt.
func (s *AccessTokenStore) LookupAccessToken(ctx context.Context, lookup storage.AccessTokenLookup) (storage.LookedUpAccessToken, error) {
	var clientID string
	var stored []byte
	var expires int64
	err := s.d.queryRow(ctx, "SELECT client_id, record, expires_at FROM {access_tokens} WHERE token_hash = ?",
		lookup.TokenHash[:]).Scan(&clientID, &stored, &expires)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return storage.LookedUpAccessToken{}, fmt.Errorf("sqlstore: look up access token: %w", notFound("access token"))
	case err != nil:
		return storage.LookedUpAccessToken{}, unavailable("look up access token", err)
	}
	out, err := s.d.decodeAccessToken(string(lookup.TokenHash[:]), clientID, stored)
	if err != nil {
		return storage.LookedUpAccessToken{}, fmt.Errorf("sqlstore: look up access token: %w", err)
	}
	out.ExpiresAt = timeOf(expires)
	return out, nil
}

// decodeAccessToken opens and decodes the record column of client
// clientID's access token keyed by key.
func (d *DB) decodeAccessToken(key, clientID string, stored []byte) (storage.LookedUpAccessToken, error) {
	plain, err := d.open(blobRef{"access_tokens", recordColumn, key, clientID}, stored)
	if err != nil {
		return storage.LookedUpAccessToken{}, err
	}
	var record accessTokenRecord
	if err := decodeRecord(plain, &record, &record.Version, accessTokenRecordVersion); err != nil {
		return storage.LookedUpAccessToken{}, err
	}
	senderConstrain, err := storage.ParseSenderConstrain(record.SenderConstrain)
	if err != nil {
		return storage.LookedUpAccessToken{}, fmt.Errorf("%w: %w: %w", ErrRecordFormat, storage.ErrStoreUnavailable, err)
	}
	return storage.LookedUpAccessToken{
		ClientID: fapi.ClientID(clientID), Subject: record.Subject, Scope: record.Scope,
		Thumbprint: record.Thumbprint, SenderConstrain: senderConstrain, Claims: record.Claims,
	}, nil
}

// Capabilities implements storage.StoreAssurance — see the package
// documentation.
func (s *AccessTokenStore) Capabilities() storage.Capabilities { return s.d.sealedCapabilities() }

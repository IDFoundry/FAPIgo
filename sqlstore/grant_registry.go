package sqlstore

import (
	"context"
	"errors"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/storage"
)

// opListGrants names ListGrants in its errors.
const opListGrants = "list grants"

// GrantRegistry returns the storage.GrantRegistry keeping d's grant
// entries: server.Dependencies.GrantRegistry. It's a
// storage.StoreAssurance with the other stores' Capabilities, and seals
// its entries with Options.Sealer.
//
// It's a method of DB, rather than of a store a wrapper might embed, as
// InteractionLookup is.
func (d *DB) GrantRegistry() storage.GrantRegistry { return grantRegistry{d} }

type grantRegistry struct{ d *DB }

func grantEntryRef(key, clientID string, expires int64) blobRef {
	return blobRef{grantRegistryTable, recordColumn, key, clientID, expires, nil}
}

// RecordGrant implements storage.GrantRegistry: one upsert.
func (r grantRegistry) RecordGrant(ctx context.Context, entry storage.NewGrantEntry) error {
	if !validTextKey(entry.Key) || !validTextKey(entry.SubjectKey) || !validTextKey(string(entry.ClientID)) {
		return errors.New("sqlstore: record grant: key, subject key or client_id isn't valid UTF-8 without NUL")
	}
	expires := nanos(entry.ExpiresAt)
	record, err := r.d.seal(grantEntryRef(entry.Key, string(entry.ClientID), expires), entry.Record)
	if err != nil {
		return unavailable("record grant", err)
	}
	err = r.d.writeOne(ctx, func(q querier) error {
		_, err := q.ExecContext(ctx, r.d.q("INSERT INTO {grant_registry} (entry_key, subject_key, client_id, record, expires_at, sweep_after) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (entry_key) DO UPDATE SET subject_key = excluded.subject_key, client_id = excluded.client_id, record = excluded.record, expires_at = excluded.expires_at, sweep_after = excluded.sweep_after"),
			entry.Key, entry.SubjectKey, string(entry.ClientID), record, expires, expires)
		return err
	})
	if err != nil {
		return unavailable("record grant", err)
	}
	return nil
}

// ListGrants implements storage.GrantRegistry: one indexed read.
func (r grantRegistry) ListGrants(ctx context.Context, listing storage.GrantListing) ([]storage.GrantEntry, error) {
	if !validTextKey(listing.SubjectKey) {
		return nil, nil
	}
	rows, err := r.d.db.QueryContext(ctx, r.d.q("SELECT entry_key, client_id, record, expires_at FROM {grant_registry} WHERE subject_key = ? AND expires_at > ?"), // NOSONAR: go:S2077 — a constant query of this package's; q substitutes only the validated TablePrefix and placeholders.
		listing.SubjectKey, nanos(listing.Now))
	if err != nil {
		return nil, unavailable(opListGrants, err)
	}
	defer func() { _ = rows.Close() }()
	var out []storage.GrantEntry
	for rows.Next() {
		var key, clientID string
		var record []byte
		var expires int64
		if err := rows.Scan(&key, &clientID, &record, &expires); err != nil {
			return nil, unavailable(opListGrants, err)
		}
		plain, err := r.d.open(grantEntryRef(key, clientID, expires), record)
		if err != nil {
			return nil, unavailable(opListGrants, err)
		}
		out = append(out, storage.GrantEntry{Key: key, ClientID: fapi.ClientID(clientID), Record: plain, ExpiresAt: timeOf(expires)})
	}
	if err := rows.Err(); err != nil {
		return nil, unavailable(opListGrants, err)
	}
	return out, nil
}

// DeleteGrant implements storage.GrantRegistry.
func (r grantRegistry) DeleteGrant(ctx context.Context, key string) error {
	if !validTextKey(key) {
		return nil
	}
	err := r.d.writeOne(ctx, func(q querier) error {
		_, err := q.ExecContext(ctx, r.d.q("DELETE FROM {grant_registry} WHERE entry_key = ?"), key)
		return err
	})
	if err != nil {
		return unavailable("delete grant", err)
	}
	return nil
}

// Capabilities implements storage.StoreAssurance — see the package
// documentation.
func (r grantRegistry) Capabilities() storage.Capabilities { return r.d.sealedCapabilities() }

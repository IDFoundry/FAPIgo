package sqlstore

import (
	"context"
	"errors"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/storage"
)

// BackchannelInbox returns the storage.BackchannelInbox keeping d's
// pending CIBA requests by end user: server.Dependencies.BackchannelInbox.
// Its entries hold the requests' backchannel authentication handles, so
// give the DB an Options.Sealer, which seals them, as it does every
// record. It's a storage.StoreAssurance with the other stores'
// Capabilities.
//
// It's a method of DB, rather than of a store a wrapper might embed, as
// InteractionLookup is.
func (d *DB) BackchannelInbox() storage.BackchannelInbox { return backchannelInbox{d} }

type backchannelInbox struct{ d *DB }

func inboxEntryRef(handleHash [32]byte, clientID string, expires int64) blobRef {
	return blobRef{backchannelInboxTable, recordColumn, string(handleHash[:]), clientID, expires, nil}
}

// AddBackchannelRequest implements storage.BackchannelInbox: one upsert.
func (b backchannelInbox) AddBackchannelRequest(ctx context.Context, entry storage.NewBackchannelInboxEntry) error {
	if !validTextKey(entry.SubjectKey) || !validTextKey(string(entry.ClientID)) {
		return errors.New("sqlstore: add backchannel request: subject key or client_id isn't valid UTF-8 without NUL")
	}
	expires := nanos(entry.ExpiresAt)
	record, err := b.d.seal(inboxEntryRef(entry.HandleHash, string(entry.ClientID), expires), entry.Record)
	if err != nil {
		return unavailable("add backchannel request", err)
	}
	err = b.d.writeOne(ctx, func(q querier) error {
		_, err := q.ExecContext(ctx, b.d.q("INSERT INTO {backchannel_inbox} (handle_hash, subject_key, client_id, record, expires_at, sweep_after) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (handle_hash) DO UPDATE SET subject_key = excluded.subject_key, client_id = excluded.client_id, record = excluded.record, expires_at = excluded.expires_at, sweep_after = excluded.sweep_after"),
			entry.HandleHash[:], entry.SubjectKey, string(entry.ClientID), record, expires, expires)
		return err
	})
	if err != nil {
		return unavailable("add backchannel request", err)
	}
	return nil
}

// ListBackchannelRequests implements storage.BackchannelInbox: one
// indexed read.
func (b backchannelInbox) ListBackchannelRequests(ctx context.Context, listing storage.BackchannelInboxListing) ([]storage.BackchannelInboxEntry, error) {
	if !validTextKey(listing.SubjectKey) {
		return nil, nil
	}
	rows, err := b.d.db.QueryContext(ctx, b.d.q("SELECT handle_hash, client_id, record, expires_at FROM {backchannel_inbox} WHERE subject_key = ? AND expires_at > ?"), // NOSONAR: go:S2077 — a constant query of this package's; q substitutes only the validated TablePrefix and placeholders.
		listing.SubjectKey, nanos(listing.Now))
	if err != nil {
		return nil, unavailable("list backchannel requests", err)
	}
	defer func() { _ = rows.Close() }()
	var out []storage.BackchannelInboxEntry
	for rows.Next() {
		var hashBytes, record []byte
		var clientID string
		var expires int64
		if err := rows.Scan(&hashBytes, &clientID, &record, &expires); err != nil {
			return nil, unavailable("list backchannel requests", err)
		}
		var hash [32]byte
		if len(hashBytes) != len(hash) {
			return nil, unavailable("list backchannel requests", errors.New("stored handle hash isn't 32 bytes"))
		}
		copy(hash[:], hashBytes)
		plain, err := b.d.open(inboxEntryRef(hash, clientID, expires), record)
		if err != nil {
			return nil, unavailable("list backchannel requests", err)
		}
		out = append(out, storage.BackchannelInboxEntry{HandleHash: hash, ClientID: fapi.ClientID(clientID), Record: plain, ExpiresAt: timeOf(expires)})
	}
	if err := rows.Err(); err != nil {
		return nil, unavailable("list backchannel requests", err)
	}
	return out, nil
}

// RemoveBackchannelRequest implements storage.BackchannelInbox.
func (b backchannelInbox) RemoveBackchannelRequest(ctx context.Context, handleHash [32]byte) error {
	err := b.d.writeOne(ctx, func(q querier) error {
		_, err := q.ExecContext(ctx, b.d.q("DELETE FROM {backchannel_inbox} WHERE handle_hash = ?"), handleHash[:])
		return err
	})
	if err != nil {
		return unavailable("remove backchannel request", err)
	}
	return nil
}

// Capabilities implements storage.StoreAssurance — see the package
// documentation.
func (b backchannelInbox) Capabilities() storage.Capabilities { return b.d.sealedCapabilities() }

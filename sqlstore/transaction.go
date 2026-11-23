package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/storage"
)

// TransactionStore is a storage.TransactionStore:
// server.Dependencies.Transactions.
type TransactionStore struct{ d *DB }

// Transactions returns d's storage.TransactionStore.
func (d *DB) Transactions() *TransactionStore { return &TransactionStore{d} }

var (
	// errRequestURIUnusable is BeginAuthorization's answer for a
	// reference that is unknown, already consumed or expired.
	errRequestURIUnusable = fmt.Errorf("sqlstore: begin authorization: %w: request_uri (unknown, already consumed or expired)", ErrNotFound)

	// errHandleUnknown is CompleteAuthorization's answer for a handle it
	// doesn't hold (unknown, completed or swept).
	errHandleUnknown = fmt.Errorf("sqlstore: complete authorization: %w: interaction handle", ErrNotFound)

	// errRequestURIConsumed is CompleteAuthorization's answer for a
	// handle whose reference another interaction completed.
	errRequestURIConsumed = errors.New("sqlstore: complete authorization: request_uri already consumed")
)

// CreatePAR implements storage.TransactionStore.
func (s *TransactionStore) CreatePAR(ctx context.Context, record storage.NewPARRecord) error {
	if !validTextKey(record.Reference) || !validTextKey(string(record.ClientID)) {
		return errors.New("sqlstore: create pushed request: reference or client_id isn't valid UTF-8 without NUL")
	}
	expires := nanos(record.ExpiresAt)
	request, err := s.d.seal(blobRef{"par_requests", requestColumn, record.Reference, string(record.ClientID), expires, nil}, record.Request)
	if err != nil {
		return unavailable("create pushed request", err)
	}
	err = s.d.writeOne(ctx, func(q querier) error {
		_, err := q.ExecContext(ctx, s.d.q("INSERT INTO {par_requests} (reference, client_id, request, expires_at, sweep_after) VALUES (?, ?, ?, ?, ?)"),
			record.Reference, string(record.ClientID), request, expires, expires)
		return err
	})
	if err != nil {
		return unavailable("create pushed request", err)
	}
	return nil
}

// beginnableRequest is the condition on par_requests matching the
// pushed request an interaction can be begun for: the row of its
// reference (the first argument), unconsumed, and not expired at the
// server's time (the second, as nanos). BeginAuthorization's UPDATE and
// the PushedRequestLookup's SELECT both select by it, each first
// answering a reference no text column can hold as unknown, so the
// lookup selects exactly the rows BeginAuthorization's UPDATE selects.
const beginnableRequest = "reference = ? AND consumed = 0 AND expires_at > ?"

// BeginAuthorization implements storage.TransactionStore. In one
// transaction, an UPDATE finds the reference unconsumed and unexpired at
// txn.Now (beginnableRequest) — locking its row — and keeps it until the
// new handle expires, then the handle is inserted with a copy of the
// request.
func (s *TransactionStore) BeginAuthorization(ctx context.Context, txn storage.BeginAuthorizationTransaction) (storage.PushedAuthorizationRequest, error) {
	if !validTextKey(txn.Reference) {
		return storage.PushedAuthorizationRequest{}, errRequestURIUnusable
	}
	if !validTextKey(txn.Handle) {
		return storage.PushedAuthorizationRequest{}, errors.New("sqlstore: begin authorization: handle isn't valid UTF-8 without NUL")
	}
	var out storage.PushedAuthorizationRequest
	handleExpires := nanos(txn.HandleExpiresAt)
	err := s.d.write(ctx, func(q querier) error {
		var clientID string
		var request []byte
		var expires int64
		err := q.QueryRowContext(ctx, s.d.q("UPDATE {par_requests} SET sweep_after = "+laterSweep+" WHERE "+beginnableRequest+" RETURNING client_id, request, expires_at"),
			handleExpires, handleExpires, txn.Reference, nanos(txn.Now)).Scan(&clientID, &request, &expires)
		if err != nil {
			return err
		}
		// The interaction's copy is sealed for its own row.
		plain, err := s.d.open(blobRef{"par_requests", requestColumn, txn.Reference, clientID, expires, nil}, request)
		if err != nil {
			return err
		}
		copied, err := s.d.seal(interactionRef(txn.Handle, clientID, txn.Reference, handleExpires), plain)
		if err != nil {
			return err
		}
		if _, err := q.ExecContext(ctx, s.d.q("INSERT INTO {interactions} (handle, reference, client_id, request, expires_at, sweep_after) VALUES (?, ?, ?, ?, ?, ?)"),
			txn.Handle, txn.Reference, clientID, copied, handleExpires, handleExpires); err != nil {
			return err
		}
		out = storage.PushedAuthorizationRequest{ClientID: fapi.ClientID(clientID), Request: plain, ExpiresAt: timeOf(expires)}
		return nil
	})
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return storage.PushedAuthorizationRequest{}, errRequestURIUnusable
	case err != nil:
		return storage.PushedAuthorizationRequest{}, unavailable("begin authorization", err)
	}
	return out, nil
}

// CompleteAuthorization implements storage.TransactionStore. In one
// transaction, a DELETE … RETURNING takes the handle, and an UPDATE
// marks its reference consumed only if it wasn't already: of
// concurrent completions for one reference, through any of its
// handles, exactly one finds it unconsumed.
func (s *TransactionStore) CompleteAuthorization(ctx context.Context, txn storage.CompleteAuthorizationTransaction) (storage.CompletedInteraction, error) {
	if !validTextKey(txn.Handle) {
		return storage.CompletedInteraction{}, errHandleUnknown
	}
	var out storage.CompletedInteraction
	err := s.d.write(ctx, func(q querier) error {
		var reference, clientID string
		var request []byte
		var expires int64
		if err := q.QueryRowContext(ctx, s.d.q("DELETE FROM {interactions} WHERE handle = ? RETURNING reference, client_id, request, expires_at"), txn.Handle).
			Scan(&reference, &clientID, &request, &expires); err != nil {
			return err
		}
		res, err := q.ExecContext(ctx, s.d.q("UPDATE {par_requests} SET consumed = 1 WHERE reference = ? AND consumed = 0"), reference)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return errRequestURIConsumed
		}
		plain, err := s.d.open(interactionRef(txn.Handle, clientID, reference, expires), request)
		if err != nil {
			return err
		}
		out = storage.CompletedInteraction{ClientID: fapi.ClientID(clientID), Request: plain, ExpiresAt: timeOf(expires)}
		return nil
	})
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return storage.CompletedInteraction{}, errHandleUnknown
	case errors.Is(err, errRequestURIConsumed):
		return storage.CompletedInteraction{}, errRequestURIConsumed
	case err != nil:
		return storage.CompletedInteraction{}, unavailable("complete authorization", err)
	}
	return out, nil
}

// Capabilities implements storage.StoreAssurance — see the package
// documentation.
func (s *TransactionStore) Capabilities() storage.Capabilities { return s.d.sealedCapabilities() }

// InteractionLookup returns the storage.InteractionLookup reading d's
// interactions: server.Dependencies.InteractionLookup, for a server
// whose Dependencies.Transactions is d.Transactions(). It's a
// storage.StoreAssurance with the TransactionStore's Capabilities.
//
// It's a method of DB, rather than of TransactionStore, so that a
// wrapper of a deployment's own that embeds *TransactionStore and
// changes how handles are keyed (a tenant prefix, say) doesn't inherit a
// lookup that reads past that: give such a wrapper a lookup keyed the
// same way.
func (d *DB) InteractionLookup() storage.InteractionLookup { return interactionLookup{d} }

type interactionLookup struct{ d *DB }

// errLookupHandleUnusable is LookupAuthorization's answer for a handle
// that is unknown, completed (through it or another handle for its
// request_uri), swept or expired.
var errLookupHandleUnusable = fmt.Errorf("sqlstore: look up interaction: %w: interaction handle (unknown, completed or expired)", ErrNotFound)

// LookupAuthorization implements storage.InteractionLookup: one read,
// outside any transaction, of the handle's row, joined to its
// request_uri's to see it unconsumed.
func (l interactionLookup) LookupAuthorization(ctx context.Context, txn storage.LookupAuthorizationTransaction) (storage.PendingInteraction, error) {
	if !validTextKey(txn.Handle) {
		return storage.PendingInteraction{}, errLookupHandleUnusable
	}
	var reference, clientID string
	var request []byte
	var expires int64
	err := l.d.queryRow(ctx, "SELECT i.reference, i.client_id, i.request, i.expires_at FROM {interactions} i JOIN {par_requests} p ON p.reference = i.reference WHERE i.handle = ? AND i.expires_at > ? AND p.consumed = 0",
		txn.Handle, nanos(txn.Now)).Scan(&reference, &clientID, &request, &expires)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return storage.PendingInteraction{}, errLookupHandleUnusable
	case err != nil:
		return storage.PendingInteraction{}, unavailable("look up interaction", err)
	}
	plain, err := l.d.open(interactionRef(txn.Handle, clientID, reference, expires), request)
	if err != nil {
		return storage.PendingInteraction{}, unavailable("look up interaction", err)
	}
	return storage.PendingInteraction{ClientID: fapi.ClientID(clientID), Request: plain, ExpiresAt: timeOf(expires)}, nil
}

// Capabilities implements storage.StoreAssurance: the TransactionStore's.
func (l interactionLookup) Capabilities() storage.Capabilities { return l.d.sealedCapabilities() }

// PushedRequestLookup returns the storage.PushedRequestLookup reading
// d's pushed requests: server.Dependencies.PushedRequestLookup, for a
// server whose Dependencies.Transactions is d.Transactions(). Set it:
// nobody has authenticated at the authorization endpoint, and without
// the lookup the server claims an interaction slot in
// Dependencies.Replay for any request_uri of its form presented there,
// with any client_id, before the TransactionStore says whether it
// exists, so anyone who can reach the endpoint can have it write a
// replay record for each request_uri they make up. With it, a
// request_uri that is unknown, expired, already used or presented with
// another client_id is refused after one read, and nothing is written.
// It's a storage.StoreAssurance with the TransactionStore's
// Capabilities, which server.New checks under AssuranceProduction.
//
// It's a method of DB, rather than of TransactionStore, for the reason
// InteractionLookup is: a wrapper of a deployment's own that embeds
// *TransactionStore and changes how references are keyed doesn't
// inherit a lookup that reads past that.
func (d *DB) PushedRequestLookup() storage.PushedRequestLookup { return pushedRequestLookup{d} }

// pushedRequestLookup is the lookup DB.PushedRequestLookup returns,
// reading d's par_requests table.
type pushedRequestLookup struct{ d *DB }

// The lookup's Capabilities are what server.New's AssuranceProduction
// gate checks, and the interface PushedRequestLookup returns doesn't
// include them.
var _ storage.StoreAssurance = pushedRequestLookup{}

// errLookupRequestURIUnusable is LookupPushedRequest's answer for a
// reference that is unknown, consumed by a completed interaction, swept
// or expired.
var errLookupRequestURIUnusable = fmt.Errorf("sqlstore: look up pushed request: %w: request_uri (unknown, already consumed or expired)", ErrNotFound)

// LookupPushedRequest implements storage.PushedRequestLookup: one read,
// outside any transaction, of the reference's row, selected as
// BeginAuthorization's UPDATE selects it (beginnableRequest), so it
// writes nothing and, on SQLite, doesn't queue behind the writes. It
// reads the row's client_id and expires_at alone, which aren't sealed,
// so it opens nothing: a Sealer binds them to the sealed request, which
// BeginAuthorization opens, and the lookup is only advisory. A row whose
// request doesn't open (sealed under another key, say) is found here,
// and BeginAuthorization, which the server still calls, answers it as
// an outage, as it would without the lookup.
func (l pushedRequestLookup) LookupPushedRequest(ctx context.Context, txn storage.LookupPushedRequestTransaction) (storage.PendingPushedRequest, error) {
	if !validTextKey(txn.Reference) {
		return storage.PendingPushedRequest{}, errLookupRequestURIUnusable
	}
	var clientID string
	var expires int64
	err := l.d.queryRow(ctx, "SELECT client_id, expires_at FROM {par_requests} WHERE "+beginnableRequest,
		txn.Reference, nanos(txn.Now)).Scan(&clientID, &expires)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return storage.PendingPushedRequest{}, errLookupRequestURIUnusable
	case err != nil:
		return storage.PendingPushedRequest{}, unavailable("look up pushed request", err)
	}
	return storage.PendingPushedRequest{ClientID: fapi.ClientID(clientID), ExpiresAt: timeOf(expires)}, nil
}

// Capabilities implements storage.StoreAssurance: the TransactionStore's.
func (l pushedRequestLookup) Capabilities() storage.Capabilities { return l.d.sealedCapabilities() }

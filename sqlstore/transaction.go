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
	err := s.d.writeOne(ctx, func(q querier) error {
		request, err := s.d.seal(blobRef{"par_requests", requestColumn, record.Reference, string(record.ClientID)}, record.Request)
		if err != nil {
			return err
		}
		_, err = q.ExecContext(ctx, s.d.q("INSERT INTO {par_requests} (reference, client_id, request, expires_at, sweep_after) VALUES (?, ?, ?, ?, ?)"),
			record.Reference, string(record.ClientID), request, expires, expires)
		return err
	})
	if err != nil {
		return unavailable("create pushed request", err)
	}
	return nil
}

// BeginAuthorization implements storage.TransactionStore. In one
// transaction, an UPDATE finds the reference unconsumed and unexpired at
// txn.Now — locking its row — and keeps it until the new handle
// expires, then the handle is inserted with a copy of the request.
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
		err := q.QueryRowContext(ctx, s.d.q("UPDATE {par_requests} SET sweep_after = "+laterSweep+" WHERE reference = ? AND consumed = 0 AND expires_at > ? RETURNING client_id, request, expires_at"),
			handleExpires, handleExpires, txn.Reference, nanos(txn.Now)).Scan(&clientID, &request, &expires)
		if err != nil {
			return err
		}
		// The interaction's copy is sealed for its own row.
		plain, err := s.d.open(blobRef{"par_requests", requestColumn, txn.Reference, clientID}, request)
		if err != nil {
			return err
		}
		copied, err := s.d.seal(blobRef{"interactions", requestColumn, txn.Handle, clientID}, plain)
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
		plain, err := s.d.open(blobRef{"interactions", requestColumn, txn.Handle, clientID}, request)
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

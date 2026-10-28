package storage

import (
	"context"
	"encoding/json"
	"time"

	fapi "github.com/idfoundry/fapigo"
)

// NewPARRecord is what CreatePAR persists for one pushed authorization
// request.
type NewPARRecord struct {
	// Reference is the lookup key: a digest the server derives from the
	// request_uri's reference component and ClientID (base64url, at most
	// 64 bytes), never the request_uri or its reference themselves, so
	// a read of the store yields no live request_uri. Opaque to the
	// store.
	Reference string

	ClientID fapi.ClientID

	// Request is the pushed request as server needs it later — opaque
	// to the store (see the package doc). BeginAuthorization and
	// CompleteAuthorization must return it unmodified.
	Request json.RawMessage

	ExpiresAt time.Time
}

// PushedAuthorizationRequest is what BeginAuthorization retrieves for
// one previously pushed authorization request. Retrieving it does not
// by itself consume the request — see BeginAuthorization's doc comment.
type PushedAuthorizationRequest struct {
	ClientID  fapi.ClientID
	Request   json.RawMessage
	ExpiresAt time.Time
}

// BeginAuthorizationTransaction is the input to
// TransactionStore.BeginAuthorization.
type BeginAuthorizationTransaction struct {
	// Reference is the key NewPARRecord.Reference was stored under, as
	// the server derives it from the request_uri presented and the
	// client_id presented with it: one presented with another
	// client_id is simply unknown.
	Reference string

	// Handle is the key of the newly generated interaction to associate
	// with this pushed authorization request's data, for retrieval when
	// the interaction later completes: a digest of the interaction
	// handle (base64url, at most 64 bytes), never the handle itself.
	Handle string

	// HandleExpiresAt bounds how long Handle remains valid.
	HandleExpiresAt time.Time

	// Now is the server's current time (server.Dependencies.Clock): a
	// Reference whose NewPARRecord.ExpiresAt isn't after it is expired,
	// and must fail without minting Handle.
	Now time.Time
}

// CompletedInteraction is what CompleteAuthorization retrieves and
// consumes for one in-progress interaction.
type CompletedInteraction struct {
	ClientID  fapi.ClientID
	Request   json.RawMessage
	ExpiresAt time.Time
}

// CompleteAuthorizationTransaction is the input to
// TransactionStore.CompleteAuthorization.
type CompleteAuthorizationTransaction struct {
	// Handle is the key BeginAuthorizationTransaction.Handle was minted
	// under, as the server derives it from the interaction handle
	// presented.
	Handle string
}

// TransactionStore persists server-side authorization-flow state.
type TransactionStore interface {
	// CreatePAR persists record under its Reference, which the server
	// generates at random, until at least its ExpiresAt. An error fails
	// the pushed authorization request.
	CreatePAR(ctx context.Context, record NewPARRecord) error

	// BeginAuthorization retrieves the pushed authorization request
	// identified by Reference and associates it with a fresh Handle for
	// retrieval when the interaction later completes. It may be called
	// more than once for the same Reference — e.g. a client's browser
	// revisiting the authorization endpoint before authenticating — and
	// each such call mints its own independent Handle for the same
	// underlying pushed request; this is what lets an authorization
	// server satisfy FAPI 2.0 Security Profile 5.3.2.2 Note 3, which
	// requires one-time use of request_uri be enforced at the point of
	// authorization, not at the point of visiting the authorization
	// endpoint. What must be single-use is completion, not the view:
	// once any Handle minted from a given Reference is successfully
	// consumed by CompleteAuthorization, that Reference itself is
	// consumed, and every subsequent BeginAuthorization or
	// CompleteAuthorization call for it — via any Handle, including
	// ones already minted and still otherwise unexpired — must fail.
	// It returns an error, and mints no Handle, if Reference is
	// unknown, already consumed by a completed interaction, or its own
	// expiry (NewPARRecord.ExpiresAt) isn't after txn.Now.
	//
	// Because a Reference can be begun again until it's consumed, its
	// request_uri is a bearer value while it's live: whoever presents it
	// can begin (and complete) an interaction for it — see
	// server.Server.BeginAuthorization.
	BeginAuthorization(ctx context.Context, txn BeginAuthorizationTransaction) (PushedAuthorizationRequest, error)

	// CompleteAuthorization atomically retrieves and consumes both the
	// interaction identified by Handle and the underlying Reference it
	// was minted from — a second call with the same Handle must fail,
	// and so must any call for a different Handle minted from the same
	// Reference, even one still otherwise valid and unexpired: exactly
	// one Handle for a given Reference may ever complete, the same way
	// an authorization code's redemption is single-use. It returns an
	// error if Handle is unknown, its Reference has already been
	// consumed by another completed interaction, or its own expiry
	// (BeginAuthorizationTransaction.HandleExpiresAt) has passed.
	CompleteAuthorization(ctx context.Context, txn CompleteAuthorizationTransaction) (CompletedInteraction, error)
}

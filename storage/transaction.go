package storage

import (
	"context"
	"encoding/json"
	"time"

	fapi "github.com/osanderson/go-fapi"
)

// NewPARRecord is what CreatePAR persists for one pushed authorization
// request.
type NewPARRecord struct {
	// Reference is the request_uri's reference component (see
	// internal/par.SplitRequestURI) — the lookup key, not the full
	// request_uri string.
	Reference string

	ClientID   fapi.ClientID
	Parameters map[string]json.RawMessage

	// TokenClaims are the already-validated extension parameter values
	// (extension.Definition.ReturnInTokenClaims) this pushed request
	// carried, keyed by wire name — the subset of Parameters that should
	// be copied into any access/ID token this authorization eventually
	// produces. A TransactionStore implementation must carry this field
	// through to PushedAuthorizationRequest and CompletedInteraction
	// unmodified, exactly as it already does for Parameters.
	TokenClaims map[string]json.RawMessage

	ExpiresAt time.Time
}

// PushedAuthorizationRequest is what BeginAuthorization retrieves for
// one previously pushed authorization request. Retrieving it does not
// by itself consume the request — see BeginAuthorization's doc comment.
type PushedAuthorizationRequest struct {
	ClientID    fapi.ClientID
	Parameters  map[string]json.RawMessage
	TokenClaims map[string]json.RawMessage
	ExpiresAt   time.Time
}

// BeginAuthorizationTransaction is the input to
// TransactionStore.BeginAuthorization.
type BeginAuthorizationTransaction struct {
	// Reference is the request_uri's reference component (see
	// internal/par.SplitRequestURI).
	Reference string

	// Handle is the newly generated interaction handle to associate with
	// this pushed authorization request's data, for retrieval when the
	// interaction later completes.
	Handle string

	// HandleExpiresAt bounds how long Handle remains valid.
	HandleExpiresAt time.Time
}

// CompletedInteraction is what CompleteAuthorization retrieves and
// consumes for one in-progress interaction.
type CompletedInteraction struct {
	ClientID    fapi.ClientID
	Parameters  map[string]json.RawMessage
	TokenClaims map[string]json.RawMessage
	ExpiresAt   time.Time
}

// CompleteAuthorizationTransaction is the input to
// TransactionStore.CompleteAuthorization.
type CompleteAuthorizationTransaction struct {
	// Handle is the interaction handle BeginAuthorization returned.
	Handle string
}

// TransactionStore persists server-side authorization-flow state.
type TransactionStore interface {
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
	// It returns an error if Reference is unknown, already consumed by
	// a completed interaction, or its own expiry
	// (NewPARRecord.ExpiresAt) has passed.
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

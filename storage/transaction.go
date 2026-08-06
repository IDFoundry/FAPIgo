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

// PushedAuthorizationRequest is what BeginAuthorization retrieves and
// consumes for one previously pushed authorization request.
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

	// BeginAuthorization atomically retrieves and consumes the pushed
	// authorization request identified by Reference — a second call
	// with the same Reference must fail, the same way an authorization
	// code's redemption is single-use — and associates it with Handle
	// for retrieval when the interaction later completes. It returns an
	// error if Reference is unknown, already consumed, or its own
	// expiry (NewPARRecord.ExpiresAt) has passed.
	BeginAuthorization(ctx context.Context, txn BeginAuthorizationTransaction) (PushedAuthorizationRequest, error)

	// CompleteAuthorization atomically retrieves and consumes the
	// interaction identified by Handle — a second call with the same
	// Handle must fail. It returns an error if Handle is unknown,
	// already consumed, or its own expiry
	// (BeginAuthorizationTransaction.HandleExpiresAt) has passed.
	CompleteAuthorization(ctx context.Context, txn CompleteAuthorizationTransaction) (CompletedInteraction, error)
}

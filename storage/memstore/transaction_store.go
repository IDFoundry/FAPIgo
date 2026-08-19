package memstore

import (
	"context"
	"fmt"
	"sync"

	"github.com/idfoundry/fapigo/storage"
)

// TransactionStore is an in-memory storage.TransactionStore. See the
// package doc comment for why this is development/testing only.
type TransactionStore struct {
	mu                 sync.Mutex
	byReference        map[string]storage.NewPARRecord
	referenceCompleted map[string]bool
	byHandle           map[string]pendingInteraction
	handleConsumed     map[string]bool
}

// pendingInteraction is what BeginAuthorization stashes per Handle: the
// reference it was minted from (needed at completion time to enforce
// single-use per Reference rather than per Handle — see
// storage.TransactionStore.BeginAuthorization's doc comment) alongside
// the data CompleteAuthorization ultimately returns.
type pendingInteraction struct {
	reference   string
	interaction storage.CompletedInteraction
}

// NewTransactionStore builds an empty TransactionStore.
func NewTransactionStore() *TransactionStore {
	return &TransactionStore{
		byReference:        make(map[string]storage.NewPARRecord),
		referenceCompleted: make(map[string]bool),
		byHandle:           make(map[string]pendingInteraction),
		handleConsumed:     make(map[string]bool),
	}
}

// CreatePAR implements storage.TransactionStore.
func (s *TransactionStore) CreatePAR(_ context.Context, record storage.NewPARRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byReference[record.Reference] = record
	return nil
}

// BeginAuthorization implements storage.TransactionStore.
func (s *TransactionStore) BeginAuthorization(_ context.Context, txn storage.BeginAuthorizationTransaction) (storage.PushedAuthorizationRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.referenceCompleted[txn.Reference] {
		return storage.PushedAuthorizationRequest{}, fmt.Errorf("memstore: request_uri already consumed")
	}
	record, ok := s.byReference[txn.Reference]
	if !ok {
		return storage.PushedAuthorizationRequest{}, fmt.Errorf("memstore: no such request_uri")
	}
	s.byHandle[txn.Handle] = pendingInteraction{
		reference: txn.Reference,
		interaction: storage.CompletedInteraction{
			ClientID: record.ClientID, Parameters: record.Parameters, TokenClaims: record.TokenClaims,
			ExpiresAt: txn.HandleExpiresAt,
		},
	}
	return storage.PushedAuthorizationRequest{
		ClientID: record.ClientID, Parameters: record.Parameters, TokenClaims: record.TokenClaims,
		ExpiresAt: record.ExpiresAt,
	}, nil
}

// CompleteAuthorization implements storage.TransactionStore.
func (s *TransactionStore) CompleteAuthorization(_ context.Context, txn storage.CompleteAuthorizationTransaction) (storage.CompletedInteraction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handleConsumed[txn.Handle] {
		return storage.CompletedInteraction{}, fmt.Errorf("memstore: interaction handle already consumed")
	}
	pending, ok := s.byHandle[txn.Handle]
	if !ok {
		return storage.CompletedInteraction{}, fmt.Errorf("memstore: no such interaction handle")
	}
	if s.referenceCompleted[pending.reference] {
		return storage.CompletedInteraction{}, fmt.Errorf("memstore: request_uri already consumed")
	}
	s.handleConsumed[txn.Handle] = true
	s.referenceCompleted[pending.reference] = true
	return pending.interaction, nil
}

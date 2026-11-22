package memstore

import (
	"context"
	"fmt"
	"sync"
	"time"

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
	record.Request = cloneRawMessage(record.Request)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byReference[record.Reference] = record
	return nil
}

// beginnable returns the pushed request reference names, if an
// interaction can be begun for it at now: it's stored, no interaction
// for it has completed, and it hasn't expired. BeginAuthorization and
// the PushedRequestLookup both ask it, so the lookup finds exactly what
// BeginAuthorization would begin. The caller holds s.mu.
func (s *TransactionStore) beginnable(reference string, now time.Time) (storage.NewPARRecord, error) {
	if s.referenceCompleted[reference] {
		return storage.NewPARRecord{}, fmt.Errorf("memstore: request_uri already consumed")
	}
	record, ok := s.byReference[reference]
	if !ok {
		return storage.NewPARRecord{}, fmt.Errorf("memstore: no such request_uri")
	}
	if !now.Before(record.ExpiresAt) {
		return storage.NewPARRecord{}, fmt.Errorf("memstore: request_uri has expired")
	}
	return record, nil
}

// BeginAuthorization implements storage.TransactionStore.
func (s *TransactionStore) BeginAuthorization(_ context.Context, txn storage.BeginAuthorizationTransaction) (storage.PushedAuthorizationRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, err := s.beginnable(txn.Reference, txn.Now)
	if err != nil {
		return storage.PushedAuthorizationRequest{}, err
	}
	s.byHandle[txn.Handle] = pendingInteraction{
		reference: txn.Reference,
		interaction: storage.CompletedInteraction{
			ClientID: record.ClientID, Request: cloneRawMessage(record.Request),
			ExpiresAt: txn.HandleExpiresAt,
		},
	}
	return storage.PushedAuthorizationRequest{
		ClientID: record.ClientID, Request: cloneRawMessage(record.Request),
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
	interaction := pending.interaction
	interaction.Request = cloneRawMessage(interaction.Request)
	return interaction, nil
}

// NewInteractionLookup returns the storage.InteractionLookup reading
// store's interactions: server.Dependencies.InteractionLookup, for a
// server whose Dependencies.Transactions is store. It's a function, not
// a method of TransactionStore, so a wrapper embedding a TransactionStore
// doesn't inherit a lookup that would read past its overrides.
func NewInteractionLookup(store *TransactionStore) storage.InteractionLookup {
	return interactionLookup{store}
}

type interactionLookup struct{ s *TransactionStore }

// LookupAuthorization implements storage.InteractionLookup.
func (l interactionLookup) LookupAuthorization(_ context.Context, txn storage.LookupAuthorizationTransaction) (storage.PendingInteraction, error) {
	s := l.s
	s.mu.Lock()
	defer s.mu.Unlock()
	pending, ok := s.byHandle[txn.Handle]
	if !ok || s.handleConsumed[txn.Handle] {
		return storage.PendingInteraction{}, fmt.Errorf("memstore: no such interaction handle")
	}
	if s.referenceCompleted[pending.reference] {
		return storage.PendingInteraction{}, fmt.Errorf("memstore: request_uri already consumed")
	}
	if !txn.Now.Before(pending.interaction.ExpiresAt) {
		return storage.PendingInteraction{}, fmt.Errorf("memstore: interaction handle has expired")
	}
	return storage.PendingInteraction{
		ClientID: pending.interaction.ClientID, Request: cloneRawMessage(pending.interaction.Request),
		ExpiresAt: pending.interaction.ExpiresAt,
	}, nil
}

// NewPushedRequestLookup returns the storage.PushedRequestLookup reading
// store's pushed requests: server.Dependencies.PushedRequestLookup, for
// a server whose Dependencies.Transactions is store. It's a function,
// not a method of TransactionStore, for the reason NewInteractionLookup
// is: a wrapper embedding a TransactionStore doesn't inherit a lookup
// that would read past its overrides.
func NewPushedRequestLookup(store *TransactionStore) storage.PushedRequestLookup {
	return pushedRequestLookup{store}
}

type pushedRequestLookup struct{ s *TransactionStore }

// LookupPushedRequest implements storage.PushedRequestLookup.
func (l pushedRequestLookup) LookupPushedRequest(_ context.Context, txn storage.LookupPushedRequestTransaction) (storage.PendingPushedRequest, error) {
	s := l.s
	s.mu.Lock()
	defer s.mu.Unlock()
	record, err := s.beginnable(txn.Reference, txn.Now)
	if err != nil {
		return storage.PendingPushedRequest{}, err
	}
	return storage.PendingPushedRequest{ClientID: record.ClientID, ExpiresAt: record.ExpiresAt}, nil
}

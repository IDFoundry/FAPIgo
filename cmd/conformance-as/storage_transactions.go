package main

import (
	"context"
	"fmt"
	"sync"

	"github.com/osanderson/go-fapi/storage"
)

// inMemoryTransactionStore is an in-memory storage.TransactionStore.
// Ported from fapitest/storage.go's memTransactionStore: same fields,
// same logic, with the *testing.T dependency dropped (it was never used
// inside the methods) so this type is usable outside a test binary.
//
// The maps here grow unboundedly for the life of the process — there is
// no expiry-driven garbage collection. That's acceptable for a
// conformance-run binary (bounded by test-run duration and count) but
// would need addressing for a longer-lived deployment.
type inMemoryTransactionStore struct {
	mu             sync.Mutex
	byReference    map[string]storage.NewPARRecord
	referenceUsed  map[string]bool
	byHandle       map[string]storage.CompletedInteraction
	handleConsumed map[string]bool
}

func newInMemoryTransactionStore() *inMemoryTransactionStore {
	return &inMemoryTransactionStore{
		byReference:    make(map[string]storage.NewPARRecord),
		referenceUsed:  make(map[string]bool),
		byHandle:       make(map[string]storage.CompletedInteraction),
		handleConsumed: make(map[string]bool),
	}
}

// CreatePAR implements storage.TransactionStore.
func (s *inMemoryTransactionStore) CreatePAR(_ context.Context, record storage.NewPARRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byReference[record.Reference] = record
	return nil
}

// BeginAuthorization implements storage.TransactionStore.
func (s *inMemoryTransactionStore) BeginAuthorization(_ context.Context, txn storage.BeginAuthorizationTransaction) (storage.PushedAuthorizationRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.referenceUsed[txn.Reference] {
		return storage.PushedAuthorizationRequest{}, fmt.Errorf("conformance-as: request_uri already consumed")
	}
	record, ok := s.byReference[txn.Reference]
	if !ok {
		return storage.PushedAuthorizationRequest{}, fmt.Errorf("conformance-as: no such request_uri")
	}
	s.referenceUsed[txn.Reference] = true
	s.byHandle[txn.Handle] = storage.CompletedInteraction{
		ClientID: record.ClientID, Parameters: record.Parameters, TokenClaims: record.TokenClaims,
		ExpiresAt: txn.HandleExpiresAt,
	}
	return storage.PushedAuthorizationRequest{
		ClientID: record.ClientID, Parameters: record.Parameters, TokenClaims: record.TokenClaims,
		ExpiresAt: record.ExpiresAt,
	}, nil
}

// CompleteAuthorization implements storage.TransactionStore.
func (s *inMemoryTransactionStore) CompleteAuthorization(_ context.Context, txn storage.CompleteAuthorizationTransaction) (storage.CompletedInteraction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handleConsumed[txn.Handle] {
		return storage.CompletedInteraction{}, fmt.Errorf("conformance-as: interaction handle already consumed")
	}
	interaction, ok := s.byHandle[txn.Handle]
	if !ok {
		return storage.CompletedInteraction{}, fmt.Errorf("conformance-as: no such interaction handle")
	}
	s.handleConsumed[txn.Handle] = true
	return interaction, nil
}

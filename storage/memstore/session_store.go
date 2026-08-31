package memstore

import (
	"context"
	"fmt"
	"sync"

	"github.com/idfoundry/fapigo/storage"
)

// SessionStore is an in-memory storage.SessionStore. See the package
// doc comment for why this is development/testing only.
type SessionStore struct {
	mu       sync.Mutex
	sessions map[string]storage.NewSession
}

// NewSessionStore builds an empty SessionStore.
func NewSessionStore() *SessionStore {
	return &SessionStore{sessions: make(map[string]storage.NewSession)}
}

// Create implements storage.SessionStore.
func (s *SessionStore) Create(_ context.Context, session storage.NewSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.State] = session
	return nil
}

// Consume implements storage.SessionStore. Deleting the map entry on
// every call — whether or not it was present — is what makes this
// single-use: a second Consume of the same State always finds nothing,
// the same discipline NonceStore.Consume applies.
func (s *SessionStore) Consume(_ context.Context, consumption storage.SessionConsumption) (storage.ConsumedSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[consumption.State]
	delete(s.sessions, consumption.State)
	if !ok {
		return storage.ConsumedSession{}, fmt.Errorf("memstore: unknown or already-consumed state")
	}
	return storage.ConsumedSession{
		Nonce: session.Nonce, PKCEVerifier: session.PKCEVerifier,
		ExpectedIssuer: session.ExpectedIssuer, ExpectedRedirectURI: session.ExpectedRedirectURI,
		ExpectedResponseMode: session.ExpectedResponseMode, ExpiresAt: session.ExpiresAt,
	}, nil
}

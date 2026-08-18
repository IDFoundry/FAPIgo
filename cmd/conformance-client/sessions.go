package main

import (
	"context"
	"fmt"
	"sync"

	"github.com/idfoundry/fapigo/storage"
)

// memSessionStore is an in-memory storage.SessionStore — this driver
// runs one authorization attempt at a time and exits, so nothing here
// needs to survive a process restart.
type memSessionStore struct {
	mu       sync.Mutex
	sessions map[string]storage.NewSession
}

func newMemSessionStore() *memSessionStore {
	return &memSessionStore{sessions: make(map[string]storage.NewSession)}
}

func (s *memSessionStore) Create(_ context.Context, session storage.NewSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.State] = session
	return nil
}

func (s *memSessionStore) Consume(_ context.Context, c storage.SessionConsumption) (storage.ConsumedSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[c.State]
	if !ok {
		return storage.ConsumedSession{}, fmt.Errorf("conformance-client: unknown or already-consumed state")
	}
	delete(s.sessions, c.State)
	return storage.ConsumedSession{
		Nonce: session.Nonce, PKCEVerifier: session.PKCEVerifier,
		ExpectedIssuer: session.ExpectedIssuer, ExpectedRedirectURI: session.ExpectedRedirectURI,
		ExpectedResponseMode: session.ExpectedResponseMode, ExpiresAt: session.ExpiresAt,
	}, nil
}

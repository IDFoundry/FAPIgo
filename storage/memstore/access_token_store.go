package memstore

import (
	"context"
	"fmt"
	"sync"

	"github.com/idfoundry/fapigo/storage"
)

// AccessTokenStore is an in-memory storage.AccessTokenStore. See the
// package doc comment for why this is development/testing only.
type AccessTokenStore struct {
	mu     sync.Mutex
	tokens map[[32]byte]storage.NewAccessToken
}

// NewAccessTokenStore builds an empty AccessTokenStore.
func NewAccessTokenStore() *AccessTokenStore {
	return &AccessTokenStore{tokens: make(map[[32]byte]storage.NewAccessToken)}
}

// CreateAccessToken implements storage.AccessTokenStore.
func (s *AccessTokenStore) CreateAccessToken(_ context.Context, tok storage.NewAccessToken) error {
	tok.Scope = cloneStrings(tok.Scope)
	tok.Claims = cloneRawMessageMap(tok.Claims)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[tok.TokenHash] = tok
	return nil
}

// LookupAccessToken implements storage.AccessTokenStore.
func (s *AccessTokenStore) LookupAccessToken(_ context.Context, lookup storage.AccessTokenLookup) (storage.LookedUpAccessToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tok, ok := s.tokens[lookup.TokenHash]
	if !ok {
		return storage.LookedUpAccessToken{}, fmt.Errorf("memstore: unknown access token")
	}
	return storage.LookedUpAccessToken{
		ClientID: tok.ClientID, Subject: tok.Subject, Scope: cloneStrings(tok.Scope),
		Thumbprint: tok.Thumbprint, Claims: cloneRawMessageMap(tok.Claims), ExpiresAt: tok.ExpiresAt,
	}, nil
}

package main

import (
	"context"
	"fmt"
	"sync"

	"github.com/osanderson/go-fapi/storage"
)

// inMemoryGrantStore is an in-memory storage.GrantStore, ported from
// fapitest/storage.go's memGrantStore — see inMemoryTransactionStore's
// doc comment for the rationale (same pattern, testing.T dropped).
type inMemoryGrantStore struct {
	mu           sync.Mutex
	codes        map[[32]byte]storage.NewAuthorizationCode
	codeRedeemed map[[32]byte]bool
	refresh      map[[32]byte]storage.NewRefreshToken
	refreshUsed  map[[32]byte]bool
}

func newInMemoryGrantStore() *inMemoryGrantStore {
	return &inMemoryGrantStore{
		codes:        make(map[[32]byte]storage.NewAuthorizationCode),
		codeRedeemed: make(map[[32]byte]bool),
		refresh:      make(map[[32]byte]storage.NewRefreshToken),
		refreshUsed:  make(map[[32]byte]bool),
	}
}

// CreateAuthorizationCode implements storage.GrantStore.
func (s *inMemoryGrantStore) CreateAuthorizationCode(_ context.Context, code storage.NewAuthorizationCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[code.CodeHash] = code
	return nil
}

// RedeemAuthorizationCode implements storage.GrantStore.
func (s *inMemoryGrantStore) RedeemAuthorizationCode(_ context.Context, redemption storage.AuthorizationCodeRedemption) (storage.RedeemedAuthorizationCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.codeRedeemed[redemption.CodeHash] {
		return storage.RedeemedAuthorizationCode{}, fmt.Errorf("conformance-as: code already redeemed")
	}
	code, ok := s.codes[redemption.CodeHash]
	if !ok {
		return storage.RedeemedAuthorizationCode{}, fmt.Errorf("conformance-as: unknown code")
	}
	s.codeRedeemed[redemption.CodeHash] = true
	return storage.RedeemedAuthorizationCode{
		ClientID: code.ClientID, RedirectURI: code.RedirectURI,
		CodeChallenge: code.CodeChallenge, CodeChallengeMethod: code.CodeChallengeMethod,
		Subject: code.Subject, Scope: code.Scope, Nonce: code.Nonce,
		AuthTime: code.AuthTime, ACR: code.ACR, AMR: code.AMR, TokenClaims: code.TokenClaims,
		ExpiresAt: code.ExpiresAt,
	}, nil
}

// CreateRefreshToken implements storage.GrantStore.
func (s *inMemoryGrantStore) CreateRefreshToken(_ context.Context, token storage.NewRefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh[token.TokenHash] = token
	return nil
}

// RedeemRefreshToken implements storage.GrantStore.
func (s *inMemoryGrantStore) RedeemRefreshToken(_ context.Context, redemption storage.RefreshTokenRedemption) (storage.RedeemedRefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.refreshUsed[redemption.TokenHash] {
		return storage.RedeemedRefreshToken{}, fmt.Errorf("conformance-as: refresh token already used")
	}
	token, ok := s.refresh[redemption.TokenHash]
	if !ok {
		return storage.RedeemedRefreshToken{}, fmt.Errorf("conformance-as: unknown refresh token")
	}
	s.refreshUsed[redemption.TokenHash] = true
	return storage.RedeemedRefreshToken{
		ClientID: token.ClientID, Subject: token.Subject, Scope: token.Scope,
		Thumbprint: token.Thumbprint, AuthTime: token.AuthTime, ACR: token.ACR, AMR: token.AMR,
		TokenClaims: token.TokenClaims, ExpiresAt: token.ExpiresAt,
	}, nil
}

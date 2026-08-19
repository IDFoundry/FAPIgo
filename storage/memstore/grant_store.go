package memstore

import (
	"context"
	"fmt"
	"sync"

	"github.com/idfoundry/fapigo/storage"
)

// GrantStore is an in-memory storage.GrantStore. See the package doc
// comment for why this is development/testing only.
type GrantStore struct {
	mu           sync.Mutex
	codes        map[[32]byte]storage.NewAuthorizationCode
	codeRedeemed map[[32]byte]bool
	refresh      map[[32]byte]storage.NewRefreshToken
}

// NewGrantStore builds an empty GrantStore.
func NewGrantStore() *GrantStore {
	return &GrantStore{
		codes:        make(map[[32]byte]storage.NewAuthorizationCode),
		codeRedeemed: make(map[[32]byte]bool),
		refresh:      make(map[[32]byte]storage.NewRefreshToken),
	}
}

// CreateAuthorizationCode implements storage.GrantStore.
func (s *GrantStore) CreateAuthorizationCode(_ context.Context, code storage.NewAuthorizationCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[code.CodeHash] = code
	return nil
}

// RedeemAuthorizationCode implements storage.GrantStore.
func (s *GrantStore) RedeemAuthorizationCode(_ context.Context, redemption storage.AuthorizationCodeRedemption) (storage.RedeemedAuthorizationCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.codeRedeemed[redemption.CodeHash] {
		return storage.RedeemedAuthorizationCode{}, fmt.Errorf("memstore: code already redeemed")
	}
	code, ok := s.codes[redemption.CodeHash]
	if !ok {
		return storage.RedeemedAuthorizationCode{}, fmt.Errorf("memstore: unknown code")
	}
	s.codeRedeemed[redemption.CodeHash] = true
	return storage.RedeemedAuthorizationCode{
		ClientID: code.ClientID, RedirectURI: code.RedirectURI,
		CodeChallenge: code.CodeChallenge, CodeChallengeMethod: code.CodeChallengeMethod,
		DPoPJKT: code.DPoPJKT,
		Subject: code.Subject, Scope: code.Scope, Nonce: code.Nonce,
		AuthTime: code.AuthTime, ACR: code.ACR, AMR: code.AMR, TokenClaims: code.TokenClaims,
		RequestedIDTokenClaims: code.RequestedIDTokenClaims, RequestedUserinfoClaims: code.RequestedUserinfoClaims,
		ExpiresAt: code.ExpiresAt,
	}, nil
}

// CreateRefreshToken implements storage.GrantStore.
func (s *GrantStore) CreateRefreshToken(_ context.Context, token storage.NewRefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh[token.TokenHash] = token
	return nil
}

// RedeemRefreshToken implements storage.GrantStore. Not single-use — see
// the interface doc comment (FAPI2-SP-FINAL 5.3.2.1-9): a refresh token
// stays valid for repeated use until it expires.
func (s *GrantStore) RedeemRefreshToken(_ context.Context, redemption storage.RefreshTokenRedemption) (storage.RedeemedRefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	token, ok := s.refresh[redemption.TokenHash]
	if !ok {
		return storage.RedeemedRefreshToken{}, fmt.Errorf("memstore: unknown refresh token")
	}
	return storage.RedeemedRefreshToken{
		ClientID: token.ClientID, Subject: token.Subject, Scope: token.Scope,
		Thumbprint: token.Thumbprint, AuthTime: token.AuthTime, ACR: token.ACR, AMR: token.AMR,
		TokenClaims:            token.TokenClaims,
		RequestedIDTokenClaims: token.RequestedIDTokenClaims, RequestedUserinfoClaims: token.RequestedUserinfoClaims,
		ExpiresAt: token.ExpiresAt,
	}, nil
}

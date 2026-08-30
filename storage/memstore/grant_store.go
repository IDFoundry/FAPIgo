package memstore

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/idfoundry/fapigo/storage"
)

// GrantStore is an in-memory storage.GrantStore. See the package doc
// comment for why this is development/testing only.
type GrantStore struct {
	mu              sync.Mutex
	codes           map[[32]byte]storage.NewAuthorizationCode
	codeRedeemed    map[[32]byte]bool
	codeAccessKey   map[[32]byte]string
	codeRefreshHash map[[32]byte][32]byte
	refresh         map[[32]byte]storage.NewRefreshToken
	refreshRevoked  map[[32]byte]bool
}

// NewGrantStore builds an empty GrantStore.
func NewGrantStore() *GrantStore {
	return &GrantStore{
		codes:           make(map[[32]byte]storage.NewAuthorizationCode),
		codeRedeemed:    make(map[[32]byte]bool),
		codeAccessKey:   make(map[[32]byte]string),
		codeRefreshHash: make(map[[32]byte][32]byte),
		refresh:         make(map[[32]byte]storage.NewRefreshToken),
		refreshRevoked:  make(map[[32]byte]bool),
	}
}

// CreateAuthorizationCode implements storage.GrantStore.
func (s *GrantStore) CreateAuthorizationCode(_ context.Context, code storage.NewAuthorizationCode) error {
	code.Scope = cloneStrings(code.Scope)
	code.AMR = cloneStrings(code.AMR)
	code.AuthorizationDetails = cloneRawMessage(code.AuthorizationDetails)
	code.TokenClaims = cloneRawMessageMap(code.TokenClaims)
	code.RequestedIDTokenClaims = cloneStrings(code.RequestedIDTokenClaims)
	code.RequestedUserinfoClaims = cloneStrings(code.RequestedUserinfoClaims)
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
		err := &storage.AuthorizationCodeAlreadyRedeemedError{
			IssuedAccessTokenKey: s.codeAccessKey[redemption.CodeHash],
		}
		if hash, ok := s.codeRefreshHash[redemption.CodeHash]; ok {
			h := hash
			err.IssuedRefreshTokenHash = &h
		}
		return storage.RedeemedAuthorizationCode{}, err
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
		Subject: code.Subject, Scope: cloneStrings(code.Scope), Nonce: code.Nonce,
		AuthTime: code.AuthTime, ACR: code.ACR, AMR: cloneStrings(code.AMR),
		AuthorizationDetails: cloneRawMessage(code.AuthorizationDetails), TokenClaims: cloneRawMessageMap(code.TokenClaims),
		RequestedIDTokenClaims: cloneStrings(code.RequestedIDTokenClaims), RequestedUserinfoClaims: cloneStrings(code.RequestedUserinfoClaims),
		ExpiresAt: code.ExpiresAt,
	}, nil
}

// RecordIssuedAccessToken implements storage.GrantStore.
func (s *GrantStore) RecordIssuedAccessToken(_ context.Context, codeHash [32]byte, key string, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codeAccessKey[codeHash] = key
	return nil
}

// RecordIssuedRefreshToken implements storage.GrantStore.
func (s *GrantStore) RecordIssuedRefreshToken(_ context.Context, codeHash [32]byte, refreshTokenHash [32]byte, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codeRefreshHash[codeHash] = refreshTokenHash
	return nil
}

// CreateRefreshToken implements storage.GrantStore.
func (s *GrantStore) CreateRefreshToken(_ context.Context, token storage.NewRefreshToken) error {
	token.Scope = cloneStrings(token.Scope)
	token.AMR = cloneStrings(token.AMR)
	token.AuthorizationDetails = cloneRawMessage(token.AuthorizationDetails)
	token.TokenClaims = cloneRawMessageMap(token.TokenClaims)
	token.RequestedIDTokenClaims = cloneStrings(token.RequestedIDTokenClaims)
	token.RequestedUserinfoClaims = cloneStrings(token.RequestedUserinfoClaims)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh[token.TokenHash] = token
	return nil
}

// RedeemRefreshToken implements storage.GrantStore. Not single-use — see
// the interface doc comment (FAPI2-SP-FINAL 5.3.2.1-9): a refresh token
// stays valid for repeated use until it expires (or is revoked — see
// RevokeRefreshToken).
func (s *GrantStore) RedeemRefreshToken(_ context.Context, redemption storage.RefreshTokenRedemption) (storage.RedeemedRefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.refreshRevoked[redemption.TokenHash] {
		return storage.RedeemedRefreshToken{}, fmt.Errorf("memstore: refresh token has been revoked")
	}
	token, ok := s.refresh[redemption.TokenHash]
	if !ok {
		return storage.RedeemedRefreshToken{}, fmt.Errorf("memstore: unknown refresh token")
	}
	return storage.RedeemedRefreshToken{
		ClientID: token.ClientID, Subject: token.Subject, Scope: cloneStrings(token.Scope),
		Thumbprint: token.Thumbprint, AuthTime: token.AuthTime, ACR: token.ACR, AMR: cloneStrings(token.AMR),
		AuthorizationDetails:   cloneRawMessage(token.AuthorizationDetails),
		TokenClaims:            cloneRawMessageMap(token.TokenClaims),
		RequestedIDTokenClaims: cloneStrings(token.RequestedIDTokenClaims), RequestedUserinfoClaims: cloneStrings(token.RequestedUserinfoClaims),
		ExpiresAt: token.ExpiresAt,
	}, nil
}

// RevokeRefreshToken implements storage.GrantStore.
func (s *GrantStore) RevokeRefreshToken(_ context.Context, tokenHash [32]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshRevoked[tokenHash] = true
	return nil
}

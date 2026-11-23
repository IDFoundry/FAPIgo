package memstore

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/idfoundry/fapigo/storage"
)

// GrantStore is an in-memory storage.GrantStore, and a
// storage.GrantRefreshTokenRevoker: it indexes each refresh token by its
// grant keys, so revoking a grant revokes the grant's refresh tokens.
// See the package doc comment for why this is development/testing only.
type GrantStore struct {
	mu              sync.Mutex
	codes           map[[32]byte]storage.NewAuthorizationCode
	codeRedeemed    map[[32]byte]bool
	codeAccessKey   map[[32]byte]string
	codeRefreshHash map[[32]byte][32]byte
	refresh         map[[32]byte]storage.NewRefreshToken
	refreshRevoked  map[[32]byte]bool

	// refreshByGrant holds the hashes of the refresh tokens created with
	// each grant key (storage.NewRefreshToken.GrantKeys), until
	// RevokeGrantRefreshTokens revokes them.
	refreshByGrant map[string][][32]byte
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
		refreshByGrant:  make(map[string][][32]byte),
	}
}

// CreateAuthorizationCode implements storage.GrantStore.
func (s *GrantStore) CreateAuthorizationCode(_ context.Context, code storage.NewAuthorizationCode) error {
	code.Grant = cloneRawMessage(code.Grant)
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
			ClientID:             s.codes[redemption.CodeHash].ClientID,
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
	if redemption.ClientID != "" && redemption.ClientID != code.ClientID {
		return storage.RedeemedAuthorizationCode{}, fmt.Errorf("memstore: code was issued to another client")
	}
	s.codeRedeemed[redemption.CodeHash] = true
	return storage.RedeemedAuthorizationCode{
		ClientID: code.ClientID, Grant: cloneRawMessage(code.Grant), ExpiresAt: code.ExpiresAt,
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

// CreateRefreshToken implements storage.GrantStore, indexing the token by
// each of its GrantKeys for RevokeGrantRefreshTokens.
func (s *GrantStore) CreateRefreshToken(_ context.Context, token storage.NewRefreshToken) error {
	token.Grant = cloneRawMessage(token.Grant)
	token.GrantKeys = cloneStrings(token.GrantKeys)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh[token.TokenHash] = token
	for _, key := range token.GrantKeys {
		s.refreshByGrant[key] = append(s.refreshByGrant[key], token.TokenHash)
	}
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
		ClientID: token.ClientID, Grant: cloneRawMessage(token.Grant), ExpiresAt: token.ExpiresAt,
	}, nil
}

// RevokeRefreshToken implements storage.GrantStore. It marks tokenHash
// revoked whether or not a token is stored under it, and keeps the mark
// for as long as the store lasts, so a token stored under the hash
// afterwards is refused too, and revoking a hash again succeeds.
func (s *GrantStore) RevokeRefreshToken(_ context.Context, tokenHash [32]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshRevoked[tokenHash] = true
	return nil
}

// RevokeGrantRefreshTokens implements storage.GrantRefreshTokenRevoker:
// it revokes each refresh token created with grantKey, as
// RevokeRefreshToken does, and reports those it revoked, leaving out any
// already revoked.
//
// A wrapper embedding this store inherits it (see
// storage.GrantRefreshTokenRevoker). Unlike the batch methods this
// package doesn't offer (see TestStoresHaveNoBatchMethods), that can
// only leave a token the wrapper keeps apart from this store unrevoked,
// never accept one the wrapper revoked: the server still checks the
// grant's revocation record on every redemption.
func (s *GrantStore) RevokeGrantRefreshTokens(_ context.Context, grantKey string) ([][32]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var revoked [][32]byte
	for _, hash := range s.refreshByGrant[grantKey] {
		if !s.refreshRevoked[hash] {
			s.refreshRevoked[hash] = true
			revoked = append(revoked, hash)
		}
	}
	delete(s.refreshByGrant, grantKey)
	return revoked, nil
}

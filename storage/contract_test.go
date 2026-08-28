package storage_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/storage"
)

// The reference implementations below are minimal, correct, in-memory
// backends whose only purpose is to prove the contract suite itself
// exercises what it claims to — every real backend (first-party or
// downstream) should run storage.TestXxxContract against its own
// factory the same way.

type refGrantStore struct {
	mu              sync.Mutex
	codes           map[[32]byte]storage.NewAuthorizationCode
	redeemed        map[[32]byte]bool
	codeAccessKey   map[[32]byte]string
	codeRefreshHash map[[32]byte][32]byte
	refresh         map[[32]byte]storage.NewRefreshToken
	refreshRevoked  map[[32]byte]bool
}

func newRefGrantStore() *refGrantStore {
	return &refGrantStore{
		codes: make(map[[32]byte]storage.NewAuthorizationCode), redeemed: make(map[[32]byte]bool),
		codeAccessKey: make(map[[32]byte]string), codeRefreshHash: make(map[[32]byte][32]byte),
		refresh: make(map[[32]byte]storage.NewRefreshToken), refreshRevoked: make(map[[32]byte]bool),
	}
}

func (s *refGrantStore) CreateAuthorizationCode(_ context.Context, code storage.NewAuthorizationCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[code.CodeHash] = code
	return nil
}

func (s *refGrantStore) RedeemAuthorizationCode(_ context.Context, r storage.AuthorizationCodeRedemption) (storage.RedeemedAuthorizationCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.redeemed[r.CodeHash] {
		err := &storage.AuthorizationCodeAlreadyRedeemedError{IssuedAccessTokenKey: s.codeAccessKey[r.CodeHash]}
		if hash, ok := s.codeRefreshHash[r.CodeHash]; ok {
			h := hash
			err.IssuedRefreshTokenHash = &h
		}
		return storage.RedeemedAuthorizationCode{}, err
	}
	code, ok := s.codes[r.CodeHash]
	if !ok {
		return storage.RedeemedAuthorizationCode{}, fmt.Errorf("unknown code")
	}
	s.redeemed[r.CodeHash] = true
	return storage.RedeemedAuthorizationCode{
		ClientID: code.ClientID, RedirectURI: code.RedirectURI,
		CodeChallenge: code.CodeChallenge, CodeChallengeMethod: code.CodeChallengeMethod,
		DPoPJKT: code.DPoPJKT,
		Subject: code.Subject, Scope: code.Scope, Nonce: code.Nonce,
		AuthTime: code.AuthTime, ACR: code.ACR, AMR: code.AMR,
		TokenClaims:            code.TokenClaims,
		RequestedIDTokenClaims: code.RequestedIDTokenClaims, RequestedUserinfoClaims: code.RequestedUserinfoClaims,
		ExpiresAt: code.ExpiresAt,
	}, nil
}

func (s *refGrantStore) RecordIssuedAccessToken(_ context.Context, codeHash [32]byte, key string, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codeAccessKey[codeHash] = key
	return nil
}

func (s *refGrantStore) RecordIssuedRefreshToken(_ context.Context, codeHash [32]byte, refreshTokenHash [32]byte, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codeRefreshHash[codeHash] = refreshTokenHash
	return nil
}

func (s *refGrantStore) CreateRefreshToken(_ context.Context, tok storage.NewRefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh[tok.TokenHash] = tok
	return nil
}

// RedeemRefreshToken is not single-use — see storage.GrantStore's doc
// comment (FAPI2-SP-FINAL 5.3.2.1-9): a refresh token stays valid for
// repeated use until it expires (or is revoked — see RevokeRefreshToken).
func (s *refGrantStore) RedeemRefreshToken(_ context.Context, r storage.RefreshTokenRedemption) (storage.RedeemedRefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.refreshRevoked[r.TokenHash] {
		return storage.RedeemedRefreshToken{}, fmt.Errorf("refresh token has been revoked")
	}
	tok, ok := s.refresh[r.TokenHash]
	if !ok {
		return storage.RedeemedRefreshToken{}, fmt.Errorf("unknown token")
	}
	return storage.RedeemedRefreshToken{
		ClientID: tok.ClientID, Subject: tok.Subject, Scope: tok.Scope,
		Thumbprint: tok.Thumbprint, AuthTime: tok.AuthTime, ACR: tok.ACR, AMR: tok.AMR,
		TokenClaims:            tok.TokenClaims,
		RequestedIDTokenClaims: tok.RequestedIDTokenClaims, RequestedUserinfoClaims: tok.RequestedUserinfoClaims,
		ExpiresAt: tok.ExpiresAt,
	}, nil
}

func (s *refGrantStore) RevokeRefreshToken(_ context.Context, tokenHash [32]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshRevoked[tokenHash] = true
	return nil
}

func TestGrantStoreContractAgainstReference(t *testing.T) {
	storage.TestGrantStoreContract(t, func() storage.GrantStore { return newRefGrantStore() })
}

type refTransactionStore struct {
	mu                 sync.Mutex
	byReference        map[string]storage.NewPARRecord
	referenceCompleted map[string]bool
	byHandle           map[string]refPendingInteraction
	handleConsumed     map[string]bool
}

// refPendingInteraction is what BeginAuthorization stashes per Handle:
// the reference it was minted from (needed at completion time to
// enforce single-use per Reference rather than per Handle — see
// storage.TransactionStore.BeginAuthorization's doc comment) alongside
// the data CompleteAuthorization ultimately returns.
type refPendingInteraction struct {
	reference   string
	interaction storage.CompletedInteraction
}

func newRefTransactionStore() *refTransactionStore {
	return &refTransactionStore{
		byReference: make(map[string]storage.NewPARRecord), referenceCompleted: make(map[string]bool),
		byHandle: make(map[string]refPendingInteraction), handleConsumed: make(map[string]bool),
	}
}

func (s *refTransactionStore) CreatePAR(_ context.Context, record storage.NewPARRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byReference[record.Reference] = record
	return nil
}

func (s *refTransactionStore) BeginAuthorization(_ context.Context, txn storage.BeginAuthorizationTransaction) (storage.PushedAuthorizationRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.referenceCompleted[txn.Reference] {
		return storage.PushedAuthorizationRequest{}, fmt.Errorf("already consumed")
	}
	record, ok := s.byReference[txn.Reference]
	if !ok {
		return storage.PushedAuthorizationRequest{}, fmt.Errorf("unknown reference")
	}
	s.byHandle[txn.Handle] = refPendingInteraction{
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

func (s *refTransactionStore) CompleteAuthorization(_ context.Context, txn storage.CompleteAuthorizationTransaction) (storage.CompletedInteraction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handleConsumed[txn.Handle] {
		return storage.CompletedInteraction{}, fmt.Errorf("already consumed")
	}
	pending, ok := s.byHandle[txn.Handle]
	if !ok {
		return storage.CompletedInteraction{}, fmt.Errorf("unknown handle")
	}
	if s.referenceCompleted[pending.reference] {
		return storage.CompletedInteraction{}, fmt.Errorf("already consumed")
	}
	s.handleConsumed[txn.Handle] = true
	s.referenceCompleted[pending.reference] = true
	return pending.interaction, nil
}

func TestTransactionStoreContractAgainstReference(t *testing.T) {
	storage.TestTransactionStoreContract(t, func() storage.TransactionStore { return newRefTransactionStore() })
}

type refReplayStore struct {
	mu   sync.Mutex
	seen map[storage.ReplayNamespace]map[[32]byte]bool
}

func newRefReplayStore() *refReplayStore {
	return &refReplayStore{seen: make(map[storage.ReplayNamespace]map[[32]byte]bool)}
}

func (s *refReplayStore) UseOnce(_ context.Context, use storage.ReplayUse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	byDigest, ok := s.seen[use.Namespace]
	if !ok {
		byDigest = make(map[[32]byte]bool)
		s.seen[use.Namespace] = byDigest
	}
	if byDigest[use.Digest] {
		return fmt.Errorf("replay detected")
	}
	byDigest[use.Digest] = true
	return nil
}

func TestReplayStoreContractAgainstReference(t *testing.T) {
	storage.TestReplayStoreContract(t, func() storage.ReplayStore { return newRefReplayStore() })
}

type refSessionStore struct {
	mu       sync.Mutex
	sessions map[string]storage.NewSession
}

func newRefSessionStore() *refSessionStore {
	return &refSessionStore{sessions: make(map[string]storage.NewSession)}
}

func (s *refSessionStore) Create(_ context.Context, session storage.NewSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.State] = session
	return nil
}

func (s *refSessionStore) Consume(_ context.Context, c storage.SessionConsumption) (storage.ConsumedSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[c.State]
	if !ok {
		return storage.ConsumedSession{}, fmt.Errorf("unknown state")
	}
	delete(s.sessions, c.State)
	return storage.ConsumedSession{
		Nonce: session.Nonce, PKCEVerifier: session.PKCEVerifier,
		ExpectedIssuer: session.ExpectedIssuer, ExpectedRedirectURI: session.ExpectedRedirectURI,
		ExpectedResponseMode: session.ExpectedResponseMode, ExpiresAt: session.ExpiresAt,
	}, nil
}

func TestSessionStoreContractAgainstReference(t *testing.T) {
	storage.TestSessionStoreContract(t, func() storage.SessionStore { return newRefSessionStore() })
}

type refAccessTokenStore struct {
	mu     sync.Mutex
	tokens map[[32]byte]storage.NewAccessToken
}

func newRefAccessTokenStore() *refAccessTokenStore {
	return &refAccessTokenStore{tokens: make(map[[32]byte]storage.NewAccessToken)}
}

func (s *refAccessTokenStore) CreateAccessToken(_ context.Context, tok storage.NewAccessToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[tok.TokenHash] = tok
	return nil
}

func (s *refAccessTokenStore) LookupAccessToken(_ context.Context, lookup storage.AccessTokenLookup) (storage.LookedUpAccessToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tok, ok := s.tokens[lookup.TokenHash]
	if !ok {
		return storage.LookedUpAccessToken{}, fmt.Errorf("unknown token")
	}
	return storage.LookedUpAccessToken{
		ClientID: tok.ClientID, Subject: tok.Subject, Scope: tok.Scope,
		Thumbprint: tok.Thumbprint, SenderConstrain: tok.SenderConstrain,
		Claims: tok.Claims, ExpiresAt: tok.ExpiresAt,
	}, nil
}

func TestAccessTokenStoreContractAgainstReference(t *testing.T) {
	storage.TestAccessTokenStoreContract(t, func() storage.AccessTokenStore { return newRefAccessTokenStore() })
}

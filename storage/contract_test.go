package storage_test

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/osanderson/go-fapi/storage"
)

// The reference implementations below are minimal, correct, in-memory
// backends whose only purpose is to prove the contract suite itself
// exercises what it claims to — every real backend (first-party or
// downstream) should run storage.TestXxxContract against its own
// factory the same way.

type refGrantStore struct {
	mu       sync.Mutex
	codes    map[[32]byte]storage.NewAuthorizationCode
	redeemed map[[32]byte]bool
	refresh  map[[32]byte]storage.NewRefreshToken
}

func newRefGrantStore() *refGrantStore {
	return &refGrantStore{
		codes: make(map[[32]byte]storage.NewAuthorizationCode), redeemed: make(map[[32]byte]bool),
		refresh: make(map[[32]byte]storage.NewRefreshToken),
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
		return storage.RedeemedAuthorizationCode{}, fmt.Errorf("already redeemed")
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

func (s *refGrantStore) CreateRefreshToken(_ context.Context, tok storage.NewRefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh[tok.TokenHash] = tok
	return nil
}

// RedeemRefreshToken is not single-use — see storage.GrantStore's doc
// comment (FAPI2-SP-FINAL 5.3.2.1-9): a refresh token stays valid for
// repeated use until it expires.
func (s *refGrantStore) RedeemRefreshToken(_ context.Context, r storage.RefreshTokenRedemption) (storage.RedeemedRefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
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

func TestGrantStoreContractAgainstReference(t *testing.T) {
	storage.TestGrantStoreContract(t, func() storage.GrantStore { return newRefGrantStore() })
}

type refTransactionStore struct {
	mu             sync.Mutex
	byReference    map[string]storage.NewPARRecord
	referenceUsed  map[string]bool
	byHandle       map[string]storage.CompletedInteraction
	handleConsumed map[string]bool
}

func newRefTransactionStore() *refTransactionStore {
	return &refTransactionStore{
		byReference: make(map[string]storage.NewPARRecord), referenceUsed: make(map[string]bool),
		byHandle: make(map[string]storage.CompletedInteraction), handleConsumed: make(map[string]bool),
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
	if s.referenceUsed[txn.Reference] {
		return storage.PushedAuthorizationRequest{}, fmt.Errorf("already consumed")
	}
	record, ok := s.byReference[txn.Reference]
	if !ok {
		return storage.PushedAuthorizationRequest{}, fmt.Errorf("unknown reference")
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

func (s *refTransactionStore) CompleteAuthorization(_ context.Context, txn storage.CompleteAuthorizationTransaction) (storage.CompletedInteraction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handleConsumed[txn.Handle] {
		return storage.CompletedInteraction{}, fmt.Errorf("already consumed")
	}
	interaction, ok := s.byHandle[txn.Handle]
	if !ok {
		return storage.CompletedInteraction{}, fmt.Errorf("unknown handle")
	}
	s.handleConsumed[txn.Handle] = true
	return interaction, nil
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

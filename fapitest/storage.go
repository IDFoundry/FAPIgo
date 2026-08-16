package fapitest

import (
	"context"
	"fmt"
	"sync"

	fapi "github.com/osanderson/go-fapi"
	"github.com/osanderson/go-fapi/storage"
)

// memClientRepository is an in-memory storage.ClientRepository holding
// exactly the one client the harness registers.
type memClientRepository struct {
	client storage.RegisteredClient
}

func (r *memClientRepository) ResolveClient(_ context.Context, id fapi.ClientID) (storage.RegisteredClient, error) {
	if id != r.client.ID() {
		return storage.RegisteredClient{}, fmt.Errorf("fapitest: unknown client %q", id)
	}
	return r.client, nil
}

// memTransactionStore is an in-memory storage.TransactionStore.
type memTransactionStore struct {
	mu             sync.Mutex
	byReference    map[string]storage.NewPARRecord
	referenceUsed  map[string]bool
	byHandle       map[string]storage.CompletedInteraction
	handleConsumed map[string]bool
}

func newMemTransactionStore() *memTransactionStore {
	return &memTransactionStore{
		byReference:    make(map[string]storage.NewPARRecord),
		referenceUsed:  make(map[string]bool),
		byHandle:       make(map[string]storage.CompletedInteraction),
		handleConsumed: make(map[string]bool),
	}
}

func (s *memTransactionStore) CreatePAR(_ context.Context, record storage.NewPARRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byReference[record.Reference] = record
	return nil
}

func (s *memTransactionStore) BeginAuthorization(_ context.Context, txn storage.BeginAuthorizationTransaction) (storage.PushedAuthorizationRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.referenceUsed[txn.Reference] {
		return storage.PushedAuthorizationRequest{}, fmt.Errorf("fapitest: request_uri already consumed")
	}
	record, ok := s.byReference[txn.Reference]
	if !ok {
		return storage.PushedAuthorizationRequest{}, fmt.Errorf("fapitest: no such request_uri")
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

func (s *memTransactionStore) CompleteAuthorization(_ context.Context, txn storage.CompleteAuthorizationTransaction) (storage.CompletedInteraction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handleConsumed[txn.Handle] {
		return storage.CompletedInteraction{}, fmt.Errorf("fapitest: interaction handle already consumed")
	}
	interaction, ok := s.byHandle[txn.Handle]
	if !ok {
		return storage.CompletedInteraction{}, fmt.Errorf("fapitest: no such interaction handle")
	}
	s.handleConsumed[txn.Handle] = true
	return interaction, nil
}

// memGrantStore is an in-memory storage.GrantStore.
type memGrantStore struct {
	mu           sync.Mutex
	codes        map[[32]byte]storage.NewAuthorizationCode
	codeRedeemed map[[32]byte]bool
	refresh      map[[32]byte]storage.NewRefreshToken
	refreshUsed  map[[32]byte]bool
}

func newMemGrantStore() *memGrantStore {
	return &memGrantStore{
		codes:        make(map[[32]byte]storage.NewAuthorizationCode),
		codeRedeemed: make(map[[32]byte]bool),
		refresh:      make(map[[32]byte]storage.NewRefreshToken),
		refreshUsed:  make(map[[32]byte]bool),
	}
}

func (s *memGrantStore) CreateAuthorizationCode(_ context.Context, code storage.NewAuthorizationCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[code.CodeHash] = code
	return nil
}

func (s *memGrantStore) RedeemAuthorizationCode(_ context.Context, redemption storage.AuthorizationCodeRedemption) (storage.RedeemedAuthorizationCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.codeRedeemed[redemption.CodeHash] {
		return storage.RedeemedAuthorizationCode{}, fmt.Errorf("fapitest: code already redeemed")
	}
	code, ok := s.codes[redemption.CodeHash]
	if !ok {
		return storage.RedeemedAuthorizationCode{}, fmt.Errorf("fapitest: unknown code")
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

func (s *memGrantStore) CreateRefreshToken(_ context.Context, token storage.NewRefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh[token.TokenHash] = token
	return nil
}

func (s *memGrantStore) RedeemRefreshToken(_ context.Context, redemption storage.RefreshTokenRedemption) (storage.RedeemedRefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.refreshUsed[redemption.TokenHash] {
		return storage.RedeemedRefreshToken{}, fmt.Errorf("fapitest: refresh token already used")
	}
	token, ok := s.refresh[redemption.TokenHash]
	if !ok {
		return storage.RedeemedRefreshToken{}, fmt.Errorf("fapitest: unknown refresh token")
	}
	s.refreshUsed[redemption.TokenHash] = true
	return storage.RedeemedRefreshToken{
		ClientID: token.ClientID, Subject: token.Subject, Scope: token.Scope,
		Thumbprint: token.Thumbprint, AuthTime: token.AuthTime, ACR: token.ACR, AMR: token.AMR,
		TokenClaims: token.TokenClaims,
		RequestedIDTokenClaims: token.RequestedIDTokenClaims, RequestedUserinfoClaims: token.RequestedUserinfoClaims,
		ExpiresAt: token.ExpiresAt,
	}, nil
}

// memReplayStore is an in-memory storage.ReplayStore shared across every
// role and namespace in the harness — namespacing is what keeps a
// client-side and server-side jti from ever colliding, exactly as
// storage.ReplayNamespace documents.
type memReplayStore struct {
	mu   sync.Mutex
	seen map[storage.ReplayNamespace]map[[32]byte]bool
}

func newMemReplayStore() *memReplayStore {
	return &memReplayStore{seen: make(map[storage.ReplayNamespace]map[[32]byte]bool)}
}

func (s *memReplayStore) UseOnce(_ context.Context, use storage.ReplayUse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	byDigest, ok := s.seen[use.Namespace]
	if !ok {
		byDigest = make(map[[32]byte]bool)
		s.seen[use.Namespace] = byDigest
	}
	if byDigest[use.Digest] {
		return fmt.Errorf("fapitest: replay detected in namespace %q", use.Namespace)
	}
	byDigest[use.Digest] = true
	return nil
}

// memSessionStore is an in-memory storage.SessionStore.
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
		return storage.ConsumedSession{}, fmt.Errorf("fapitest: unknown or already-consumed state")
	}
	delete(s.sessions, c.State)
	return storage.ConsumedSession{
		Nonce: session.Nonce, PKCEVerifier: session.PKCEVerifier,
		ExpectedIssuer: session.ExpectedIssuer, ExpectedRedirectURI: session.ExpectedRedirectURI,
		ExpectedResponseMode: session.ExpectedResponseMode, ExpiresAt: session.ExpiresAt,
	}, nil
}

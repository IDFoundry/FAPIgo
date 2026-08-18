package fapitest

import (
	"context"
	"fmt"
	"sync"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/storage"
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
	mu                 sync.Mutex
	byReference        map[string]storage.NewPARRecord
	referenceCompleted map[string]bool
	byHandle           map[string]memPendingInteraction
	handleConsumed     map[string]bool
}

// memPendingInteraction is what BeginAuthorization stashes per Handle:
// the reference it was minted from (needed at completion time to
// enforce single-use per Reference rather than per Handle — see
// storage.TransactionStore.BeginAuthorization's doc comment) alongside
// the data CompleteAuthorization ultimately returns.
type memPendingInteraction struct {
	reference   string
	interaction storage.CompletedInteraction
}

func newMemTransactionStore() *memTransactionStore {
	return &memTransactionStore{
		byReference:        make(map[string]storage.NewPARRecord),
		referenceCompleted: make(map[string]bool),
		byHandle:           make(map[string]memPendingInteraction),
		handleConsumed:     make(map[string]bool),
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
	if s.referenceCompleted[txn.Reference] {
		return storage.PushedAuthorizationRequest{}, fmt.Errorf("fapitest: request_uri already consumed")
	}
	record, ok := s.byReference[txn.Reference]
	if !ok {
		return storage.PushedAuthorizationRequest{}, fmt.Errorf("fapitest: no such request_uri")
	}
	s.byHandle[txn.Handle] = memPendingInteraction{
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

func (s *memTransactionStore) CompleteAuthorization(_ context.Context, txn storage.CompleteAuthorizationTransaction) (storage.CompletedInteraction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handleConsumed[txn.Handle] {
		return storage.CompletedInteraction{}, fmt.Errorf("fapitest: interaction handle already consumed")
	}
	pending, ok := s.byHandle[txn.Handle]
	if !ok {
		return storage.CompletedInteraction{}, fmt.Errorf("fapitest: no such interaction handle")
	}
	if s.referenceCompleted[pending.reference] {
		return storage.CompletedInteraction{}, fmt.Errorf("fapitest: request_uri already consumed")
	}
	s.handleConsumed[txn.Handle] = true
	s.referenceCompleted[pending.reference] = true
	return pending.interaction, nil
}

// memGrantStore is an in-memory storage.GrantStore.
type memGrantStore struct {
	mu           sync.Mutex
	codes        map[[32]byte]storage.NewAuthorizationCode
	codeRedeemed map[[32]byte]bool
	refresh      map[[32]byte]storage.NewRefreshToken
}

func newMemGrantStore() *memGrantStore {
	return &memGrantStore{
		codes:        make(map[[32]byte]storage.NewAuthorizationCode),
		codeRedeemed: make(map[[32]byte]bool),
		refresh:      make(map[[32]byte]storage.NewRefreshToken),
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

// RedeemRefreshToken is not single-use — see storage.GrantStore's doc
// comment (FAPI2-SP-FINAL 5.3.2.1-9): a refresh token stays valid for
// repeated use until it expires.
func (s *memGrantStore) RedeemRefreshToken(_ context.Context, redemption storage.RefreshTokenRedemption) (storage.RedeemedRefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	token, ok := s.refresh[redemption.TokenHash]
	if !ok {
		return storage.RedeemedRefreshToken{}, fmt.Errorf("fapitest: unknown refresh token")
	}
	return storage.RedeemedRefreshToken{
		ClientID: token.ClientID, Subject: token.Subject, Scope: token.Scope,
		Thumbprint: token.Thumbprint, AuthTime: token.AuthTime, ACR: token.ACR, AMR: token.AMR,
		TokenClaims:            token.TokenClaims,
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

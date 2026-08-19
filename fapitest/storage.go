package fapitest

import (
	"context"
	"fmt"
	"sync"
	"time"

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
	mu              sync.Mutex
	codes           map[[32]byte]storage.NewAuthorizationCode
	codeRedeemed    map[[32]byte]bool
	codeAccessJTI   map[[32]byte]string
	codeRefreshHash map[[32]byte][32]byte
	refresh         map[[32]byte]storage.NewRefreshToken
	refreshRevoked  map[[32]byte]bool
}

func newMemGrantStore() *memGrantStore {
	return &memGrantStore{
		codes:           make(map[[32]byte]storage.NewAuthorizationCode),
		codeRedeemed:    make(map[[32]byte]bool),
		codeAccessJTI:   make(map[[32]byte]string),
		codeRefreshHash: make(map[[32]byte][32]byte),
		refresh:         make(map[[32]byte]storage.NewRefreshToken),
		refreshRevoked:  make(map[[32]byte]bool),
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
		err := &storage.AuthorizationCodeAlreadyRedeemedError{IssuedAccessTokenJTI: s.codeAccessJTI[redemption.CodeHash]}
		if hash, ok := s.codeRefreshHash[redemption.CodeHash]; ok {
			h := hash
			err.IssuedRefreshTokenHash = &h
		}
		return storage.RedeemedAuthorizationCode{}, err
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

func (s *memGrantStore) RecordIssuedAccessToken(_ context.Context, codeHash [32]byte, jti string, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codeAccessJTI[codeHash] = jti
	return nil
}

func (s *memGrantStore) RecordIssuedRefreshToken(_ context.Context, codeHash [32]byte, refreshTokenHash [32]byte, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codeRefreshHash[codeHash] = refreshTokenHash
	return nil
}

func (s *memGrantStore) CreateRefreshToken(_ context.Context, token storage.NewRefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh[token.TokenHash] = token
	return nil
}

// RedeemRefreshToken is not single-use — see storage.GrantStore's doc
// comment (FAPI2-SP-FINAL 5.3.2.1-9): a refresh token stays valid for
// repeated use until it expires (or is revoked — see RevokeRefreshToken).
func (s *memGrantStore) RedeemRefreshToken(_ context.Context, redemption storage.RefreshTokenRedemption) (storage.RedeemedRefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.refreshRevoked[redemption.TokenHash] {
		return storage.RedeemedRefreshToken{}, fmt.Errorf("fapitest: refresh token has been revoked")
	}
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

func (s *memGrantStore) RevokeRefreshToken(_ context.Context, tokenHash [32]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshRevoked[tokenHash] = true
	return nil
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

// memRevocationStore is an in-memory store shared across the harness's
// server and resource verifier — mirroring memReplayStore's sharing
// pattern above — implementing both server.RevocationSink and
// resource.RevocationChecker.
type memRevocationStore struct {
	mu      sync.Mutex
	revoked map[string]bool
}

func newMemRevocationStore() *memRevocationStore {
	return &memRevocationStore{revoked: make(map[string]bool)}
}

func (s *memRevocationStore) Revoke(_ context.Context, jti string, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revoked[jti] = true
	return nil
}

func (s *memRevocationStore) IsRevoked(_ context.Context, jti string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revoked[jti], nil
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

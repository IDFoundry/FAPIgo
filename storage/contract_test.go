package storage_test

import (
	"context"
	"encoding/json"
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
		AuthorizationDetails:   code.AuthorizationDetails,
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
		AuthorizationDetails:   tok.AuthorizationDetails,
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

type refNonceStore struct {
	mu     sync.Mutex
	nonces map[string]storage.NonceIssuance
}

func newRefNonceStore() *refNonceStore {
	return &refNonceStore{nonces: make(map[string]storage.NonceIssuance)}
}

func (s *refNonceStore) Issue(_ context.Context, issuance storage.NonceIssuance) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nonces[issuance.Nonce] = issuance
	return nil
}

func (s *refNonceStore) Consume(_ context.Context, c storage.NonceConsumption) (storage.NonceRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	issuance, ok := s.nonces[c.Nonce]
	if !ok {
		return storage.NonceRecord{}, fmt.Errorf("unknown nonce")
	}
	delete(s.nonces, c.Nonce)
	return storage.NonceRecord{ExpiresAt: issuance.ExpiresAt}, nil
}

func TestNonceStoreContractAgainstReference(t *testing.T) {
	storage.TestNonceStoreContract(t, func() storage.NonceStore { return newRefNonceStore() })
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

type refBackchannelAuthenticationRecord struct {
	record               storage.NewBackchannelAuthentication
	status               storage.BackchannelAuthenticationStatus
	subject              string
	scope                []string
	authorizationDetails json.RawMessage
	authTime             time.Time
	acr                  string
	amr                  []string
	reason               string
	redeemed             bool
	polledBefore         bool
	lastPolledAt         time.Time
}

type refBackchannelAuthenticationStore struct {
	mu              sync.Mutex
	byAuthReqIDHash map[[32]byte]*refBackchannelAuthenticationRecord
	byHandleHash    map[[32]byte]*refBackchannelAuthenticationRecord
}

func newRefBackchannelAuthenticationStore() *refBackchannelAuthenticationStore {
	return &refBackchannelAuthenticationStore{
		byAuthReqIDHash: make(map[[32]byte]*refBackchannelAuthenticationRecord),
		byHandleHash:    make(map[[32]byte]*refBackchannelAuthenticationRecord),
	}
}

func (s *refBackchannelAuthenticationStore) CreateBackchannelAuthentication(_ context.Context, record storage.NewBackchannelAuthentication) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := &refBackchannelAuthenticationRecord{record: record, status: storage.BackchannelAuthenticationPending}
	s.byAuthReqIDHash[record.AuthReqIDHash] = rec
	s.byHandleHash[record.HandleHash] = rec
	return nil
}

func (s *refBackchannelAuthenticationStore) LookupBackchannelAuthentication(_ context.Context, handleHash [32]byte) (storage.LookedUpBackchannelAuthentication, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.byHandleHash[handleHash]
	if !ok {
		return storage.LookedUpBackchannelAuthentication{}, fmt.Errorf("unknown backchannel authentication handle")
	}
	return storage.LookedUpBackchannelAuthentication{
		ClientID:   rec.record.ClientID,
		Parameters: rec.record.Parameters,
	}, nil
}

func (s *refBackchannelAuthenticationStore) DecideBackchannelAuthentication(_ context.Context, decision storage.DecideBackchannelAuthentication) (storage.DecidedBackchannelAuthentication, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.byHandleHash[decision.HandleHash]
	if !ok {
		return storage.DecidedBackchannelAuthentication{}, fmt.Errorf("unknown backchannel authentication handle")
	}
	if rec.status != storage.BackchannelAuthenticationPending {
		return storage.DecidedBackchannelAuthentication{}, fmt.Errorf("backchannel authentication request already decided")
	}
	rec.status = decision.Status
	rec.subject = decision.Subject
	rec.scope = decision.Scope
	rec.authorizationDetails = decision.AuthorizationDetails
	rec.authTime = decision.AuthTime
	rec.acr = decision.ACR
	rec.amr = decision.AMR
	rec.reason = decision.Reason
	if rec.record.DeliveryMode == "ping" {
		// See memstore's identical reset for why — CIBA Core 1.0 §10.2's
		// ping notification exempts the client's next poll from the
		// interval check.
		rec.polledBefore = false
	}
	return storage.DecidedBackchannelAuthentication{
		ClientID:                rec.record.ClientID,
		DeliveryMode:            rec.record.DeliveryMode,
		ClientNotificationToken: rec.record.ClientNotificationToken,
		AuthReqID:               rec.record.AuthReqID,
	}, nil
}

func (s *refBackchannelAuthenticationStore) PollBackchannelAuthentication(_ context.Context, poll storage.PollBackchannelAuthentication) (storage.PolledBackchannelAuthentication, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.byAuthReqIDHash[poll.AuthReqIDHash]
	if !ok {
		return storage.PolledBackchannelAuthentication{}, fmt.Errorf("unknown auth_req_id")
	}
	if rec.redeemed {
		return storage.PolledBackchannelAuthentication{}, &storage.BackchannelAuthenticationAlreadyRedeemedError{}
	}
	if !poll.Now.Before(rec.record.ExpiresAt) {
		return storage.PolledBackchannelAuthentication{}, &storage.BackchannelAuthenticationExpiredError{}
	}
	if rec.polledBefore && poll.Now.Sub(rec.lastPolledAt) < rec.record.PollInterval {
		rec.lastPolledAt = poll.Now
		return storage.PolledBackchannelAuthentication{}, &storage.BackchannelAuthenticationSlowDownError{}
	}
	rec.polledBefore = true
	rec.lastPolledAt = poll.Now
	if rec.status == storage.BackchannelAuthenticationApproved {
		rec.redeemed = true
	}
	return storage.PolledBackchannelAuthentication{
		Status: rec.status, ClientID: rec.record.ClientID,
		Subject: rec.subject, Scope: rec.scope, AuthorizationDetails: rec.authorizationDetails,
		AuthTime: rec.authTime, ACR: rec.acr, AMR: rec.amr,
		TokenClaims: rec.record.TokenClaims, DPoPJKT: rec.record.DPoPJKT, Reason: rec.reason,
		RequestedIDTokenClaims:  rec.record.RequestedIDTokenClaims,
		RequestedUserinfoClaims: rec.record.RequestedUserinfoClaims,
	}, nil
}

func TestBackchannelAuthenticationStoreContractAgainstReference(t *testing.T) {
	storage.TestBackchannelAuthenticationStoreContract(t, func() storage.BackchannelAuthenticationStore {
		return newRefBackchannelAuthenticationStore()
	})
}

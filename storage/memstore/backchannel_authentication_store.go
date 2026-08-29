package memstore

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/storage"
)

// backchannelRecord is one pending or decided CIBA backchannel
// authentication request, shared (by pointer) between
// BackchannelAuthenticationStore's two lookup maps.
type backchannelRecord struct {
	clientID                fapi.ClientID
	parameters              map[string]json.RawMessage
	tokenClaims             map[string]json.RawMessage
	requestedIDTokenClaims  []string
	requestedUserinfoClaims []string
	deliveryMode            string
	clientNotificationToken fapi.Secret
	authReqID               string
	dpopJKT                 string
	pollInterval            time.Duration
	expiresAt               time.Time

	status   storage.BackchannelAuthenticationStatus
	subject  string
	scope    []string
	authTime time.Time
	acr      string
	amr      []string
	reason   string

	redeemed     bool
	polledBefore bool
	lastPolledAt time.Time
}

// BackchannelAuthenticationStore is an in-memory
// storage.BackchannelAuthenticationStore. See the package doc comment
// for why this is development/testing only.
type BackchannelAuthenticationStore struct {
	mu              sync.Mutex
	byAuthReqIDHash map[[32]byte]*backchannelRecord
	byHandleHash    map[[32]byte]*backchannelRecord
}

// NewBackchannelAuthenticationStore builds an empty
// BackchannelAuthenticationStore.
func NewBackchannelAuthenticationStore() *BackchannelAuthenticationStore {
	return &BackchannelAuthenticationStore{
		byAuthReqIDHash: make(map[[32]byte]*backchannelRecord),
		byHandleHash:    make(map[[32]byte]*backchannelRecord),
	}
}

// CreateBackchannelAuthentication implements
// storage.BackchannelAuthenticationStore.
func (s *BackchannelAuthenticationStore) CreateBackchannelAuthentication(_ context.Context, record storage.NewBackchannelAuthentication) error {
	rec := &backchannelRecord{
		clientID:                record.ClientID,
		parameters:              cloneRawMessageMap(record.Parameters),
		tokenClaims:             cloneRawMessageMap(record.TokenClaims),
		requestedIDTokenClaims:  cloneStrings(record.RequestedIDTokenClaims),
		requestedUserinfoClaims: cloneStrings(record.RequestedUserinfoClaims),
		deliveryMode:            record.DeliveryMode,
		clientNotificationToken: record.ClientNotificationToken,
		authReqID:               record.AuthReqID,
		dpopJKT:                 record.DPoPJKT,
		pollInterval:            record.PollInterval,
		expiresAt:               record.ExpiresAt,
		status:                  storage.BackchannelAuthenticationPending,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byAuthReqIDHash[record.AuthReqIDHash] = rec
	s.byHandleHash[record.HandleHash] = rec
	return nil
}

// DecideBackchannelAuthentication implements
// storage.BackchannelAuthenticationStore.
func (s *BackchannelAuthenticationStore) DecideBackchannelAuthentication(_ context.Context, decision storage.DecideBackchannelAuthentication) (storage.DecidedBackchannelAuthentication, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.byHandleHash[decision.HandleHash]
	if !ok {
		return storage.DecidedBackchannelAuthentication{}, fmt.Errorf("memstore: no such backchannel authentication handle")
	}
	if rec.status != storage.BackchannelAuthenticationPending {
		return storage.DecidedBackchannelAuthentication{}, fmt.Errorf("memstore: backchannel authentication request already decided")
	}
	rec.status = decision.Status
	rec.subject = decision.Subject
	rec.scope = cloneStrings(decision.Scope)
	rec.authTime = decision.AuthTime
	rec.acr = decision.ACR
	rec.amr = cloneStrings(decision.AMR)
	rec.reason = decision.Reason
	if rec.deliveryMode == "ping" {
		// CIBA Core 1.0 §10.2: ping delivery's whole point is letting the
		// client skip the usual PollInterval wait once notified — the
		// notification itself is the "go ahead", not another metered
		// poll attempt. Resetting polledBefore exempts exactly the next
		// PollBackchannelAuthentication call from the interval check
		// below, the same as a genuinely first poll — confirmed
		// necessary live against the OIDF suite's own
		// fapi-ciba-id1-ping-* modules, which call the token endpoint
		// immediately on receiving the ping and require success, not
		// slow_down.
		rec.polledBefore = false
	}
	return storage.DecidedBackchannelAuthentication{
		ClientID:                rec.clientID,
		DeliveryMode:            rec.deliveryMode,
		ClientNotificationToken: rec.clientNotificationToken,
		AuthReqID:               rec.authReqID,
	}, nil
}

// PollBackchannelAuthentication implements
// storage.BackchannelAuthenticationStore.
func (s *BackchannelAuthenticationStore) PollBackchannelAuthentication(_ context.Context, poll storage.PollBackchannelAuthentication) (storage.PolledBackchannelAuthentication, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.byAuthReqIDHash[poll.AuthReqIDHash]
	if !ok {
		return storage.PolledBackchannelAuthentication{}, fmt.Errorf("memstore: no such auth_req_id")
	}
	if rec.redeemed {
		return storage.PolledBackchannelAuthentication{}, &storage.BackchannelAuthenticationAlreadyRedeemedError{}
	}
	if !poll.Now.Before(rec.expiresAt) {
		return storage.PolledBackchannelAuthentication{}, &storage.BackchannelAuthenticationExpiredError{}
	}
	if rec.polledBefore && poll.Now.Sub(rec.lastPolledAt) < rec.pollInterval {
		rec.lastPolledAt = poll.Now
		return storage.PolledBackchannelAuthentication{}, &storage.BackchannelAuthenticationSlowDownError{}
	}
	rec.polledBefore = true
	rec.lastPolledAt = poll.Now

	if rec.status == storage.BackchannelAuthenticationApproved {
		rec.redeemed = true
	}
	return storage.PolledBackchannelAuthentication{
		Status:                  rec.status,
		ClientID:                rec.clientID,
		Subject:                 rec.subject,
		Scope:                   cloneStrings(rec.scope),
		AuthTime:                rec.authTime,
		ACR:                     rec.acr,
		AMR:                     cloneStrings(rec.amr),
		TokenClaims:             cloneRawMessageMap(rec.tokenClaims),
		DPoPJKT:                 rec.dpopJKT,
		Reason:                  rec.reason,
		RequestedIDTokenClaims:  cloneStrings(rec.requestedIDTokenClaims),
		RequestedUserinfoClaims: cloneStrings(rec.requestedUserinfoClaims),
	}, nil
}

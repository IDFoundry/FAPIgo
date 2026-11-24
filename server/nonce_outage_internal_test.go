package server

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// lookupFailingNonceStore issues nonces into a working store, and
// answers every Lookup with lookupErr.
type lookupFailingNonceStore struct {
	storage.NonceStore
	lookupErr error
}

func (s lookupFailingNonceStore) Lookup(context.Context, storage.NonceLookup) (storage.NonceRecord, error) {
	return storage.NonceRecord{}, s.lookupErr
}

// TestCheckDPoPNonceAnswersALookupOutageWithServerError: a nonce Lookup
// the store couldn't answer is a 500 server_error, not a use_dpop_nonce
// challenge the client would retry forever, while a nonce the store
// doesn't know still gets the challenge with the current nonce.
func TestCheckDPoPNonceAnswersALookupOutageWithServerError(t *testing.T) {
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	for name, tc := range map[string]struct {
		ctx       context.Context
		lookupErr error
		want      ErrorCode
		status    int
	}{
		"store unavailable":   {context.Background(), fmt.Errorf("nonces: %w", storage.ErrStoreUnavailable), ErrorServerError, 500},
		"deadline exceeded":   {context.Background(), fmt.Errorf("nonces: %w", context.DeadlineExceeded), ErrorServerError, 500},
		"request ended first": {ended, errors.New("nonces: no answer"), ErrorServerError, 500},
		"unknown nonce":       {context.Background(), errors.New("nonces: unknown nonce"), ErrorUseDPoPNonce, 400},
	} {
		t.Run(name, func(t *testing.T) {
			store := lookupFailingNonceStore{NonceStore: memstore.NewNonceStore(), lookupErr: tc.lookupErr}
			s := &Server{deps: Dependencies{Nonces: store, Random: rand.Reader}}
			s.cfg.Limits.DPoPNonceLifetime = time.Minute
			err := s.checkDPoPNonce(tc.ctx, "presented-nonce", time.Now())
			if err == nil || err.Code() != tc.want || err.HTTPStatus() != tc.status {
				t.Fatalf("checkDPoPNonce = %v, want %s (%d)", err, tc.want, tc.status)
			}
			if tc.want == ErrorUseDPoPNonce && err.Nonce() == "" {
				t.Error("the challenge carries no nonce")
			}
			if tc.want == ErrorServerError && err.Nonce() != "" {
				t.Error("the server_error carries a nonce challenge")
			}
		})
	}
}

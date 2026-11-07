package server_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/internal/grantrevocation"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// batchRevocationSink is a fakeRevocationSink that is also a
// storage.RevocationBatchChecker, logging each IsAnyRevoked call's keys
// and each IsRevoked call. batchErr, if set, is what IsAnyRevoked
// returns.
type batchRevocationSink struct {
	*fakeRevocationSink

	mu       sync.Mutex
	batches  [][]string
	singles  int
	batchErr error
}

var _ storage.RevocationBatchChecker = (*batchRevocationSink)(nil)

func (b *batchRevocationSink) IsRevoked(ctx context.Context, key string) (bool, error) {
	b.mu.Lock()
	b.singles++
	b.mu.Unlock()
	return b.fakeRevocationSink.IsRevoked(ctx, key)
}

func (b *batchRevocationSink) IsAnyRevoked(_ context.Context, keys []string) (bool, error) {
	b.mu.Lock()
	b.batches = append(b.batches, slices.Clone(keys))
	err := b.batchErr
	b.mu.Unlock()
	if err != nil {
		return false, err
	}
	revoked := b.all()
	for _, key := range keys {
		if slices.Contains(revoked, key) {
			return true, nil
		}
	}
	return false, nil
}

// TestRefreshChecksTheGrantRevocationInOneBatch: with a
// storage.RevocationBatchChecker revocation store, a refresh checks its
// code grant's current and pre-v0.61.0 keys in one IsAnyRevoked call and
// no IsRevoked call, and keeps the responses of the per-key check:
// invalid_grant once the grant is revoked, server_error (never a pass)
// when the store fails.
func TestRefreshChecksTheGrantRevocationInOneBatch(t *testing.T) {
	for _, tc := range []struct {
		name     string
		revoke   func(codeGrantID string) string
		batchErr error
		want     server.ErrorCode
	}{
		{name: "NotRevoked"},
		{name: "Revoked", revoke: func(id string) string { return grantrevocation.CodeKey(testIssuer, id) }, want: server.ErrorInvalidGrant},
		{name: "RevokedBeforeV0.61.0", revoke: func(id string) string { return "code-grant:" + id }, want: server.ErrorInvalidGrant},
		{name: "StoreFails", batchErr: errors.New("down"), want: server.ErrorServerError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, sink := newBatchRevocationHarness(t)
			dpopKey := generateKey(t)
			refreshToken, codeGrantID := exchangeForRefreshToken(t, h, dpopKey)
			if tc.revoke != nil {
				if err := h.revocation.Revoke(context.Background(), tc.revoke(codeGrantID), h.now.Add(time.Hour)); err != nil {
					t.Fatalf("Revoke: %v", err)
				}
			}
			sink.mu.Lock()
			sink.batches, sink.singles, sink.batchErr = nil, 0, tc.batchErr
			sink.mu.Unlock()

			_, err := h.server.RefreshAccessToken(context.Background(), server.RefreshTokenRequest{
				HTTP:       server.FormRequest{Parameters: refreshFormParams(h.clientAssertion(t), refreshToken, "")},
				DPoPProofs: []string{createDPoPProof(t, dpopKey, h.now)},
			})
			requireTokenOutcome(t, err, tc.want)
			wantKeys := grantrevocation.CodeKeys(testIssuer, codeGrantID)
			if len(sink.batches) != 1 || !slices.Equal(sink.batches[0], wantKeys) || sink.singles != 0 {
				t.Fatalf("IsAnyRevoked calls = %v, IsRevoked calls = %d; want one IsAnyRevoked(%v) and no IsRevoked", sink.batches, sink.singles, wantKeys)
			}
		})
	}
}

// newBatchRevocationHarness is newHarness with its revocation sink
// wrapped in a batchRevocationSink.
func newBatchRevocationHarness(t *testing.T) (harness, *batchRevocationSink) {
	t.Helper()
	h := newHarness(t, server.ProfileFAPISecurity, true)
	sink := &batchRevocationSink{fakeRevocationSink: h.revocation}
	deps := h.deps
	deps.Revocation = sink
	srv, err := server.New(h.cfg, deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	h.server = srv
	h.deps = deps
	return h, sink
}

// exchangeForRefreshToken authorizes and exchanges a code with
// "offline_access", returning the refresh token and the code grant ID it
// carries.
func exchangeForRefreshToken(t *testing.T, h harness, dpopKey *ecdsa.PrivateKey) (refreshToken, codeGrantID string) {
	t.Helper()
	code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts", "offline_access"})
	result, err := exchangeCode(t, h, code, dpopKey)
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	// The digest the server stores a code under (authorizationCodeHash).
	return result.RefreshToken.Reveal(), grantrevocation.CodeGrantID(sha256.Sum256([]byte("fapigo authorization code\x00" + code)))
}

// requireTokenOutcome fails unless err is nil when want is empty, or a
// *server.Error with want otherwise.
func requireTokenOutcome(t *testing.T, err error, want server.ErrorCode) {
	t.Helper()
	if want == "" {
		if err != nil {
			t.Fatalf("token request: %v", err)
		}
		return
	}
	var serr *server.Error
	if !errors.As(err, &serr) || serr.Code() != want {
		t.Fatalf("token request = %v, want %s", err, want)
	}
}

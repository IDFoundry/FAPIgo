package server_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"slices"
	"sync"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/token"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// recordingGrantStore is a fakeGrantStore that is also a
// storage.IssuedTokensRecorder, logging the calls a code exchange makes
// after redeeming the code. beforeCreateRefreshToken, if set, runs at the
// start of CreateRefreshToken, outside every lock — the point between
// redeeming a code and recording what it issued.
type recordingGrantStore struct {
	*fakeGrantStore

	mu    sync.Mutex
	calls []string
	// recorded is RecordIssuedTokens' last arguments.
	recorded struct {
		codeHash                         [32]byte
		accessKey                        string
		accessExpiresAt, refreshExpireAt time.Time
		refreshHash                      [32]byte
	}

	beforeCreateRefreshToken func()
}

func (r *recordingGrantStore) log(call string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, call)
}

func (r *recordingGrantStore) loggedCalls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.calls)
}

func (r *recordingGrantStore) CreateRefreshToken(ctx context.Context, tok storage.NewRefreshToken) error {
	if hook := r.beforeCreateRefreshToken; hook != nil {
		r.beforeCreateRefreshToken = nil
		hook()
	}
	r.log("CreateRefreshToken")
	return r.fakeGrantStore.CreateRefreshToken(ctx, tok)
}

func (r *recordingGrantStore) RecordIssuedAccessToken(ctx context.Context, codeHash [32]byte, key string, expiresAt time.Time) error {
	r.log("RecordIssuedAccessToken")
	return r.fakeGrantStore.RecordIssuedAccessToken(ctx, codeHash, key, expiresAt)
}

func (r *recordingGrantStore) RecordIssuedRefreshToken(ctx context.Context, codeHash [32]byte, refreshTokenHash [32]byte, expiresAt time.Time) error {
	r.log("RecordIssuedRefreshToken")
	return r.fakeGrantStore.RecordIssuedRefreshToken(ctx, codeHash, refreshTokenHash, expiresAt)
}

func (r *recordingGrantStore) RecordIssuedTokens(ctx context.Context, codeHash [32]byte, accessKey string, accessExpiresAt time.Time, refreshHash [32]byte, refreshExpiresAt time.Time) error {
	r.log("RecordIssuedTokens")
	r.mu.Lock()
	r.recorded.codeHash, r.recorded.accessKey, r.recorded.accessExpiresAt = codeHash, accessKey, accessExpiresAt
	r.recorded.refreshHash, r.recorded.refreshExpireAt = refreshHash, refreshExpiresAt
	r.mu.Unlock()
	if err := r.fakeGrantStore.RecordIssuedAccessToken(ctx, codeHash, accessKey, accessExpiresAt); err != nil {
		return err
	}
	return r.fakeGrantStore.RecordIssuedRefreshToken(ctx, codeHash, refreshHash, refreshExpiresAt)
}

// newRecordingHarness is newHarness with its grant store wrapped in a
// recordingGrantStore, so the server finds a storage.IssuedTokensRecorder.
func newRecordingHarness(t *testing.T) (harness, *recordingGrantStore) {
	t.Helper()
	h := newHarness(t, server.ProfileFAPISecurity, true)
	store := &recordingGrantStore{fakeGrantStore: h.grants}
	deps := h.deps
	deps.Grants = store
	srv, err := server.New(h.cfg, deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	h.server = srv
	h.deps = deps
	return h, store
}

func exchangeCode(t *testing.T, h harness, code string, dpopKey *ecdsa.PrivateKey) (server.TokenResult, error) {
	t.Helper()
	return h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:       server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
		DPoPProofs: []string{createDPoPProof(t, dpopKey, h.now)},
	})
}

func accessTokenJTI(t *testing.T, h harness, accessToken string) string {
	t.Helper()
	parsed, err := token.ParseAccessToken(accessToken)
	if err != nil {
		t.Fatalf("ParseAccessToken: %v", err)
	}
	validated, err := parsed.Validate(&h.serverKey.PublicKey, token.AccessTokenValidatePolicy{
		ExpectedIssuer: testIssuer, ExpectedAudience: testIssuer,
		Algorithm: fapi.ES256, Now: h.now, MaxLifetime: 10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Validate access token: %v", err)
	}
	return validated.JTI
}

// TestExchangeAuthorizationCodeRecordsBothTokensInOneWrite: with a
// storage.IssuedTokensRecorder grant store and a refresh token to issue,
// the exchange issues the refresh token first and records both tokens in
// one RecordIssuedTokens call, with the same values the two-call form
// records; without "offline_access" it records the access token alone,
// as before.
func TestExchangeAuthorizationCodeRecordsBothTokensInOneWrite(t *testing.T) {
	for _, tc := range []struct {
		name  string
		scope []string
		want  []string
	}{
		{"WithRefreshToken", []string{"openid", "accounts", "offline_access"}, []string{"CreateRefreshToken", "RecordIssuedTokens"}},
		{"WithoutRefreshToken", []string{"openid", "accounts"}, []string{"RecordIssuedAccessToken"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, store := newRecordingHarness(t)
			code := completeSuccessfulAuthorization(t, h, tc.scope)
			result, err := exchangeCode(t, h, code, generateKey(t))
			if err != nil {
				t.Fatalf("ExchangeAuthorizationCode: %v", err)
			}
			if got := store.loggedCalls(); !slices.Equal(got, tc.want) {
				t.Fatalf("grant store calls = %v, want %v", got, tc.want)
			}
			if result.HasRefreshToken {
				requireRecordedTokens(t, h, store, code, result)
			}
		})
	}
}

// requireRecordedTokens fails unless store's RecordIssuedTokens call
// recorded code's exchange result, with each token's lifetime.
func requireRecordedTokens(t *testing.T, h harness, store *recordingGrantStore, code string, result server.TokenResult) {
	t.Helper()
	got := store.recorded
	wantCodeHash := sha256.Sum256([]byte("fapigo authorization code\x00" + code))
	if got.codeHash != wantCodeHash || got.accessKey != accessTokenJTI(t, h, result.AccessToken.Reveal()) ||
		got.refreshHash != sha256.Sum256([]byte(result.RefreshToken.Reveal())) {
		t.Fatalf("RecordIssuedTokens recorded code %x, access key %q, refresh hash %x; want the exchange's code and tokens", got.codeHash, got.accessKey, got.refreshHash)
	}
	if !got.accessExpiresAt.Equal(h.now.Add(h.cfg.Limits.AccessTokenLifetime)) || !got.refreshExpireAt.Equal(h.now.Add(h.cfg.Limits.RefreshTokenLifetime)) {
		t.Fatalf("RecordIssuedTokens expiries = %v, %v, want now plus each token's lifetime", got.accessExpiresAt, got.refreshExpireAt)
	}
}

// TestCodeReuseRevokesTokensRecordedInOneWrite is
// TestExchangeAuthorizationCodeReuseRevokesRefreshToken over a
// storage.IssuedTokensRecorder: a reuse after the exchange revokes the
// access token by its key and the refresh token itself (RFC 6749
// §4.1.2).
func TestCodeReuseRevokesTokensRecordedInOneWrite(t *testing.T) {
	h, _ := newRecordingHarness(t)
	code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts", "offline_access"})
	first, err := exchangeCode(t, h, code, generateKey(t))
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	if _, err := exchangeCode(t, h, code, generateKey(t)); err == nil {
		t.Fatal("second ExchangeAuthorizationCode (reused code) = nil error, want error")
	}
	if jti := accessTokenJTI(t, h, first.AccessToken.Reveal()); !slices.Contains(h.revocation.all(), jti) {
		t.Fatalf("Revoke calls = %v, want the first access token's jti %q among them", h.revocation.all(), jti)
	}
	refreshHash := sha256.Sum256([]byte(first.RefreshToken.Reveal()))
	h.grants.mu.Lock()
	revoked := h.grants.refreshRevoked[refreshHash]
	h.grants.mu.Unlock()
	if !revoked {
		t.Fatal("the first refresh token wasn't revoked")
	}
}

// TestCodeReuseBeforeTheRecordStillEndsTheTokens: a reuse that reads the
// code after it was redeemed but before RecordIssuedTokens has recorded
// what it issued finds no token keys to revoke — as a reuse before
// RecordIssuedAccessToken does in the two-call form — yet both tokens
// the first exchange then returns are refused: the reuse revokes the
// code's grant, which each token carries. Without the reuse, the same
// tokens work.
func TestCodeReuseBeforeTheRecordStillEndsTheTokens(t *testing.T) {
	t.Run("NoReuse", func(t *testing.T) {
		verifyErr, refreshErr := useTokensAfterExchange(t, false)
		if verifyErr != nil || refreshErr != nil {
			t.Fatalf("Verify = %v, RefreshAccessToken = %v, want both to succeed", verifyErr, refreshErr)
		}
	})
	t.Run("ReuseMidExchange", func(t *testing.T) {
		verifyErr, refreshErr := useTokensAfterExchange(t, true)
		requireInvalidToken(t, verifyErr, "access token issued after the reuse")
		if refreshErr == nil {
			t.Fatal("RefreshAccessToken with a refresh token issued after the reuse = nil error, want the grant refused")
		}
	})
}

// useTokensAfterExchange exchanges a code with "offline_access" over a
// recordingGrantStore — reusing the code mid-exchange, between its
// redemption and RecordIssuedTokens, when reuse is set — and then uses
// both tokens: the access token at a resource server, the refresh token
// to refresh.
func useTokensAfterExchange(t *testing.T, reuse bool) (verifyErr, refreshErr error) {
	t.Helper()
	h, store := newRecordingHarness(t)
	code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts", "offline_access"})
	var reuseErr error
	if reuse {
		store.beforeCreateRefreshToken = func() {
			_, reuseErr = exchangeCode(t, h, code, generateKey(t))
		}
	}
	dpopKey := generateKey(t)
	first, err := exchangeCode(t, h, code, dpopKey)
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	if reuse && reuseErr == nil {
		t.Fatal("ExchangeAuthorizationCode reusing the code mid-exchange = nil error, want error")
	}
	if got := store.loggedCalls(); !slices.Equal(got, []string{"CreateRefreshToken", "RecordIssuedTokens"}) {
		t.Fatalf("grant store calls = %v, want the refresh token issued, then both tokens recorded", got)
	}
	verifyErr = verifyWithDPoP(t, embedderResourceVerifier(t, h, nil), dpopKey, first.AccessToken.Reveal(), h.now)
	_, refreshErr = h.server.RefreshAccessToken(context.Background(), server.RefreshTokenRequest{
		HTTP:       server.FormRequest{Parameters: refreshFormParams(h.clientAssertion(t), first.RefreshToken.Reveal(), "")},
		DPoPProofs: []string{createDPoPProof(t, dpopKey, h.now)},
	})
	return verifyErr, refreshErr
}

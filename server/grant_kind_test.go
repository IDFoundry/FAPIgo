package server_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// unifiedGrantRow is one row of unifiedGrantStore's single table.
type unifiedGrantRow struct {
	clientID    fapi.ClientID
	grant       []byte
	expiresAt   time.Time
	refresh     bool
	redeemed    bool
	revoked     bool
	accessKey   string
	refreshHash *[32]byte
}

// unifiedGrantStore keeps authorization codes and refresh tokens in one
// table keyed by digest, as a GrantStore backed by a single "grants"
// table might, and otherwise keeps GrantStore's contract (it passes
// every subtest but the cross-kind ones).
//
// With crossed set it also stands in for a store whose lookup is
// broken outright: a redemption of a digest it doesn't know returns the
// most recently created row of the other kind. That reaches the
// server's check of the record's own kind even when the digests differ.
type unifiedGrantStore struct {
	crossed bool

	mu                    sync.Mutex
	rows                  map[[32]byte]*unifiedGrantRow
	lastCode, lastRefresh *unifiedGrantRow
}

func newUnifiedGrantStore(crossed bool) *unifiedGrantStore {
	return &unifiedGrantStore{crossed: crossed, rows: map[[32]byte]*unifiedGrantRow{}}
}

func (s *unifiedGrantStore) lookup(hash [32]byte, fallback *unifiedGrantRow) (*unifiedGrantRow, bool) {
	if row, ok := s.rows[hash]; ok {
		return row, true
	}
	if s.crossed && fallback != nil {
		return fallback, true
	}
	return nil, false
}

func (s *unifiedGrantStore) CreateAuthorizationCode(_ context.Context, c storage.NewAuthorizationCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	row := &unifiedGrantRow{clientID: c.ClientID, grant: append([]byte(nil), c.Grant...), expiresAt: c.ExpiresAt}
	s.rows[c.CodeHash] = row
	s.lastCode = row
	return nil
}

func (s *unifiedGrantStore) RedeemAuthorizationCode(_ context.Context, r storage.AuthorizationCodeRedemption) (storage.RedeemedAuthorizationCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row, ok := s.lookup(r.CodeHash, s.lastRefresh)
	if !ok {
		return storage.RedeemedAuthorizationCode{}, errors.New("unknown authorization code")
	}
	if row.redeemed {
		return storage.RedeemedAuthorizationCode{}, &storage.AuthorizationCodeAlreadyRedeemedError{IssuedAccessTokenKey: row.accessKey, IssuedRefreshTokenHash: row.refreshHash, ClientID: row.clientID}
	}
	if r.ClientID != "" && r.ClientID != row.clientID {
		return storage.RedeemedAuthorizationCode{}, errors.New("authorization code was issued to another client")
	}
	if !row.refresh {
		row.redeemed = true
	}
	return storage.RedeemedAuthorizationCode{ClientID: row.clientID, Grant: append([]byte(nil), row.grant...), ExpiresAt: row.expiresAt}, nil
}

func (s *unifiedGrantStore) RecordIssuedAccessToken(_ context.Context, codeHash [32]byte, key string, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if row, ok := s.rows[codeHash]; ok {
		row.accessKey = key
	}
	return nil
}

func (s *unifiedGrantStore) RecordIssuedRefreshToken(_ context.Context, codeHash, refreshTokenHash [32]byte, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if row, ok := s.rows[codeHash]; ok {
		row.refreshHash = &refreshTokenHash
	}
	return nil
}

func (s *unifiedGrantStore) CreateRefreshToken(_ context.Context, tok storage.NewRefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	row := &unifiedGrantRow{clientID: tok.ClientID, grant: append([]byte(nil), tok.Grant...), expiresAt: tok.ExpiresAt, refresh: true}
	s.rows[tok.TokenHash] = row
	s.lastRefresh = row
	return nil
}

func (s *unifiedGrantStore) RedeemRefreshToken(_ context.Context, r storage.RefreshTokenRedemption) (storage.RedeemedRefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row, ok := s.lookup(r.TokenHash, s.lastCode)
	if !ok || row.revoked {
		return storage.RedeemedRefreshToken{}, errors.New("unknown or revoked refresh token")
	}
	return storage.RedeemedRefreshToken{ClientID: row.clientID, Grant: append([]byte(nil), row.grant...), ExpiresAt: row.expiresAt}, nil
}

func (s *unifiedGrantStore) RevokeRefreshToken(_ context.Context, hash [32]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if row, ok := s.rows[hash]; ok {
		row.revoked = true
	}
	return nil
}

// newHarnessWithGrantStore is newHarness with grants as its GrantStore.
func newHarnessWithGrantStore(t *testing.T, grants storage.GrantStore) harness {
	t.Helper()
	h := newHarness(t, server.ProfileFAPISecurity, true)
	deps := h.deps
	deps.Grants = grants
	srv, err := server.New(h.cfg, deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	h.server = srv
	return h
}

// unifiedGrantStoreCases are the stores the cross-kind tests run
// against: one table keyed by digest, which the digests' domain
// separation already keeps apart, and one whose lookup crosses kinds
// outright, which only the record's own kind refuses.
var unifiedGrantStoreCases = []struct {
	name    string
	crossed bool
}{
	{name: "unified table", crossed: false},
	{name: "crossed lookup", crossed: true},
}

// TestAuthorizationCodeRefusedAtRefreshGrant covers an authorization
// code presented as a refresh_token: refused with invalid_grant, so it
// can't skip the code exchange's PKCE, redirect_uri, DPoP binding and
// single use, and left unspent for the client's own exchange.
func TestAuthorizationCodeRefusedAtRefreshGrant(t *testing.T) {
	for _, tc := range unifiedGrantStoreCases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarnessWithGrantStore(t, newUnifiedGrantStore(tc.crossed))
			code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts"})
			if _, err := refreshWith(t, h, code, ""); serverErrorCode(t, err) != server.ErrorInvalidGrant {
				t.Fatalf("code presented as refresh_token: %v, want invalid_grant", err)
			}
			if _, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
				HTTP:       server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
				DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
			}); err != nil {
				t.Fatalf("code exchange after the refused refresh: %v", err)
			}
		})
	}
}

// TestRefreshTokenRefusedAtCodeExchange covers the reverse: a refresh
// token presented as a code is refused with invalid_grant, and the
// refresh token still works.
func TestRefreshTokenRefusedAtCodeExchange(t *testing.T) {
	for _, tc := range unifiedGrantStoreCases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarnessWithGrantStore(t, newUnifiedGrantStore(tc.crossed))
			tokens, _ := exchangeForTokensWithOfflineAccess(t, h)
			refreshToken := tokens.RefreshToken.Reveal()
			_, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
				HTTP:       server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), refreshToken, testRedirectURI, testCodeVerifier)},
				DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
			})
			if serverErrorCode(t, err) != server.ErrorInvalidGrant {
				t.Fatalf("refresh token presented as code: %v, want invalid_grant", err)
			}
			if _, err := refreshWith(t, h, refreshToken, ""); err != nil {
				t.Fatalf("refresh after the refused code exchange: %v", err)
			}
		})
	}
}

package server_test

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// settableClock is a Clock a test moves forward, shared by a server and
// a revocation store that honours record expiry.
type settableClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *settableClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *settableClock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}

// expiringRevocationStore forgets a record once its expiresAt passes, as
// a store with native TTL (Redis, DynamoDB) does, which RevocationSink's
// doc invites.
type expiringRevocationStore struct {
	clock *settableClock
	mu    sync.Mutex
	until map[string]time.Time
}

func (s *expiringRevocationStore) Revoke(_ context.Context, key string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.until == nil {
		s.until = map[string]time.Time{}
	}
	s.until[key] = expiresAt
	return nil
}

func (s *expiringRevocationStore) IsRevoked(_ context.Context, key string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	until, ok := s.until[key]
	return ok && s.clock.Now().Before(until), nil
}

// rebuild is h with a server built over the same stores from mutated
// config and dependencies, and h.now moved to clock's time, as after an
// operator changed Limits and restarted.
func rebuild(t *testing.T, h harness, mutate func(*server.Config), deps server.Dependencies) harness {
	t.Helper()
	cfg := h.cfg
	mutate(&cfg)
	srv, err := server.New(cfg, deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	h.server = srv
	h.now = deps.Clock.Now()
	return h
}

// exchangeWithGrantID runs an authorization granting offline_access under
// grantID and redeems the code, returning the refresh token.
func exchangeWithGrantID(t *testing.T, h harness, grantID string) string {
	t.Helper()
	handle := beginInteractionRequestingScope(t, h, "openid accounts offline_access")
	result, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
		Handle: handle, Result: authorizeWithGrantID(t, h.now, grantID, "openid", "accounts", "offline_access"),
	})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	redirect, ok := result.(server.AuthorizationRedirect)
	if !ok {
		t.Fatalf("CompleteAuthorization = %T, want a redirect", result)
	}
	dest := redirect.Destination().URL()
	tokens, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:       server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), dest.Query().Get("code"), testRedirectURI, testCodeVerifier)},
		DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
	})
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	return tokens.RefreshToken.Reveal()
}

// TestRevokedGrantStaysRevokedAfterRefreshLifetimeShortened is the review's
// scenario: a refresh token issued under a 1h lifetime, the lifetime then
// lowered to 10m, the grant revoked. RevokeGrant's record lasts the
// current horizon only, so once it lapses the refresh token must already
// count as expired, judged by its issue time and the current lifetime.
func TestRevokedGrantStaysRevokedAfterRefreshLifetimeShortened(t *testing.T) {
	start := time.Now()
	clock := &settableClock{now: start}
	store := &expiringRevocationStore{clock: clock}
	h := newHarness(t, server.ProfileFAPISecurity, true)
	deps := h.deps
	deps.Clock = clock
	deps.Revocation = store
	h = rebuild(t, h, func(c *server.Config) { c.Limits.RefreshTokenLifetime = time.Hour }, deps)

	refreshToken := exchangeWithGrantID(t, h, "grant-1")

	shortened := func(c *server.Config) { c.Limits.RefreshTokenLifetime = 10 * time.Minute }
	h = rebuild(t, h, shortened, deps)
	if err := h.server.RevokeGrant(context.Background(), "grant-1"); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}

	// Within the revocation record: refused as revoked.
	clock.set(start.Add(time.Minute))
	h = rebuild(t, h, shortened, deps)
	if _, err := refreshWith(t, h, refreshToken, ""); serverErrorCode(t, err) != server.ErrorInvalidGrant {
		t.Fatalf("refresh 1m after revocation: %v, want invalid_grant", err)
	}

	// The record has lapsed, but the token was issued more than the
	// current 10m lifetime ago: refused as expired, not resurrected.
	clock.set(start.Add(26 * time.Minute))
	h = rebuild(t, h, shortened, deps)
	if revoked, _ := store.IsRevoked(context.Background(), "grant:grant-1"); revoked {
		t.Fatal("test setup: the revocation record should have lapsed by now")
	}
	if _, err := refreshWith(t, h, refreshToken, ""); serverErrorCode(t, err) != server.ErrorInvalidGrant {
		t.Fatalf("refresh 26m on, after the revocation record lapsed: %v, want invalid_grant", err)
	}
}

// TestRefreshTokenExpiresWithShortenedLifetime covers the rule without a
// revocation: a refresh token issued under a longer lifetime expires at
// its issue time plus the current one, and is unaffected before then.
func TestRefreshTokenExpiresWithShortenedLifetime(t *testing.T) {
	start := time.Now()
	clock := &settableClock{now: start}
	h := newHarness(t, server.ProfileFAPISecurity, true)
	deps := h.deps
	deps.Clock = clock
	h = rebuild(t, h, func(c *server.Config) { c.Limits.RefreshTokenLifetime = time.Hour }, deps)
	tokens, _ := exchangeForTokensWithOfflineAccess(t, h)
	shortened := func(c *server.Config) { c.Limits.RefreshTokenLifetime = 10 * time.Minute }

	clock.set(start.Add(5 * time.Minute))
	h = rebuild(t, h, shortened, deps)
	if _, err := refreshWith(t, h, tokens.RefreshToken.Reveal(), ""); err != nil {
		t.Fatalf("refresh within the shortened lifetime: %v", err)
	}
	clock.set(start.Add(11 * time.Minute))
	h = rebuild(t, h, shortened, deps)
	if _, err := refreshWith(t, h, tokens.RefreshToken.Reveal(), ""); serverErrorCode(t, err) != server.ErrorInvalidGrant {
		t.Fatalf("refresh past the shortened lifetime: %v, want invalid_grant", err)
	}
}

// TestRefreshTokenWithoutIssueTimeKeepsStoredExpiry covers a refresh token
// written before records carried an issue time: it keeps its stored
// expiry, as before.
func TestRefreshTokenWithoutIssueTimeKeepsStoredExpiry(t *testing.T) {
	start := time.Now()
	clock := &settableClock{now: start}
	h := newHarness(t, server.ProfileFAPISecurity, true)
	deps := h.deps
	deps.Clock = clock
	h = rebuild(t, h, func(c *server.Config) { c.Limits.RefreshTokenLifetime = time.Hour }, deps)
	tokens, _ := exchangeForTokensWithOfflineAccess(t, h)

	h.grants.mu.Lock()
	for hash, stored := range h.grants.refreshByHash {
		var record map[string]json.RawMessage
		if err := json.Unmarshal(stored.Grant, &record); err != nil {
			t.Fatal(err)
		}
		if _, ok := record["issued_at"]; !ok {
			t.Fatalf("stored refresh grant has no issued_at: %s", stored.Grant)
		}
		delete(record, "issued_at")
		stored.Grant, _ = json.Marshal(record)
		h.grants.refreshByHash[hash] = stored
	}
	h.grants.mu.Unlock()

	clock.set(start.Add(30 * time.Minute))
	h = rebuild(t, h, func(c *server.Config) { c.Limits.RefreshTokenLifetime = 10 * time.Minute }, deps)
	if _, err := refreshWith(t, h, tokens.RefreshToken.Reveal(), ""); err != nil {
		t.Fatalf("refresh of an older record within its stored expiry: %v", err)
	}
}

// TestAuthorizationCodeExpiresWithShortenedLifetime covers a code issued
// under a longer lifetime, redeemed after the lifetime was shortened.
func TestAuthorizationCodeExpiresWithShortenedLifetime(t *testing.T) {
	start := time.Now()
	clock := &settableClock{now: start}
	h := newHarness(t, server.ProfileFAPISecurity, true)
	deps := h.deps
	deps.Clock = clock
	h = rebuild(t, h, func(c *server.Config) { c.Limits.AuthorizationCodeLifetime = 5 * time.Minute }, deps)
	code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts"})

	clock.set(start.Add(2 * time.Minute))
	h = rebuild(t, h, func(c *server.Config) { c.Limits.AuthorizationCodeLifetime = time.Minute }, deps)
	_, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:       server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
		DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
	})
	if serverErrorCode(t, err) != server.ErrorInvalidGrant {
		t.Fatalf("exchange past the shortened code lifetime: %v, want invalid_grant", err)
	}
}

// TestCIBADecisionExpiresWithShortenedLifetime covers an approved CIBA
// request collected after its lifetime was shortened.
func TestCIBADecisionExpiresWithShortenedLifetime(t *testing.T) {
	start := time.Now()
	clock := &settableClock{now: start}
	var cfg server.Config
	var deps server.Dependencies
	h := newHarnessWithBackchannelOptions(t, memstore.NewBackchannelAuthenticationStore(), func(c *server.Config) {
		c.Limits.BackchannelAuthenticationRequestLifetime = 2 * time.Minute
		c.Limits.MaxBackchannelAuthenticationRequestLifetime = 2 * time.Minute
		cfg = *c
	}, func(d *server.Dependencies) {
		d.Clock = clock
		deps = *d
	})
	h.now = start
	params := standardBackchannelParams(t)
	required := beginBackchannel(t, h, params)
	if err := h.server.CompleteBackchannelAuthentication(context.Background(), server.CompleteBackchannelAuthenticationRequest{
		Handle: required.Handle, Result: authorizeWithGrantID(t, h.now, ""),
	}); err != nil {
		t.Fatalf("CompleteBackchannelAuthentication: %v", err)
	}

	clock.set(start.Add(90 * time.Second))
	cfg.Limits.BackchannelAuthenticationRequestLifetime = time.Minute
	srv, err := server.New(cfg, deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	h.server, h.now = srv, clock.Now()
	_, err = h.server.ExchangeBackchannelAuthentication(context.Background(), server.BackchannelTokenExchangeRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_assertion", h.clientAssertion(t)),
			formParam("client_assertion_type", clientassertion.AssertionType),
			formParam("grant_type", server.CIBAGrantType),
			formParam("auth_req_id", required.AuthReqID.String()),
		}},
		DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
	})
	if serverErrorCode(t, err) != server.ErrorExpiredToken {
		t.Fatalf("CIBA exchange past the shortened lifetime: %v, want expired_token", err)
	}
}

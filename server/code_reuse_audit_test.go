package server_test

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// notAllRevoked is the description of a revoking reuse audited as a
// failure.
const notAllRevoked = "the tokens issued from the code could not all be revoked"

// TestRevokingCodeReuseIsAudited covers a reuse by the code's own
// client: audited as AuditEventRevokeReusedAuthorizationCode, then the
// exchange's own failure, and as a failed revocation when one of its
// writes failed, so something issued from the code may still work.
func TestRevokingCodeReuseIsAudited(t *testing.T) {
	for name, tc := range map[string]struct {
		breakRevocation func(harness)
		want            server.AuditEvent
	}{
		"revoked": {
			func(harness) {},
			server.AuditEvent{Outcome: server.AuditOutcomeSuccess},
		},
		"revocation store failing": {
			func(h harness) { h.revocation.fail = errStoreDown },
			server.AuditEvent{Outcome: server.AuditOutcomeFailure, Description: notAllRevoked},
		},
		"refresh token revocation failing": {
			func(h harness) { h.grants.failRevokeRefresh = errStoreDown },
			server.AuditEvent{Outcome: server.AuditOutcomeFailure, Description: notAllRevoked},
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, server.ProfileFAPISecurity, true)
			dpopKey := generateKey(t)
			code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts", "offline_access"})
			if _, err := exchangeCode(t, h, code, dpopKey); err != nil {
				t.Fatalf("ExchangeAuthorizationCode: %v", err)
			}
			tc.breakRevocation(h)
			audited := len(h.audit.all())
			_, err := exchangeCode(t, h, code, dpopKey)
			requireInvalidGrant(t, err)
			requireRevokingReuseAudited(t, h.audit.all()[audited:], tc.want)
		})
	}
}

// requireRevokingReuseAudited fails unless events are a revoking reuse
// by testClientID with want's outcome and description, then the
// exchange's own failure.
func requireRevokingReuseAudited(t *testing.T, events []server.AuditEvent, want server.AuditEvent) {
	t.Helper()
	if len(events) != 2 {
		t.Fatalf("audit events = %+v, want the revocation and the exchange's failure", events)
	}
	revocation, exchange := events[0], events[1]
	if revocation.Type != server.AuditEventRevokeReusedAuthorizationCode || revocation.ClientID != testClientID ||
		revocation.Outcome != want.Outcome || revocation.Description != want.Description {
		t.Errorf("revocation audit event = %+v, want the reused code's revocation by %s, outcome %v, description %q", revocation, testClientID, want.Outcome, want.Description)
	}
	if exchange.Type != server.AuditEventExchangeAuthorizationCode || exchange.Outcome != server.AuditOutcomeFailure {
		t.Errorf("exchange audit event = %+v, want a failed ExchangeAuthorizationCode", exchange)
	}
}

// requireNoRevokingReuseAudited fails if events record a revoking reuse.
func requireNoRevokingReuseAudited(t *testing.T, events []server.AuditEvent) {
	t.Helper()
	for _, e := range events {
		if e.Type == server.AuditEventRevokeReusedAuthorizationCode {
			t.Fatalf("a revoking reuse was audited: %+v", e)
		}
	}
}

// TestCodeReuseByAnotherClientAuditsNoRevocation: another client's
// reuse of a code revokes nothing, so no revocation is audited.
func TestCodeReuseByAnotherClientAuditsNoRevocation(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	if !issueAndReuse(t, h) {
		t.Fatal("another client's reuse of the code revoked the original client's refresh token")
	}
	requireNoRevokingReuseAudited(t, h.audit.all())
}

// TestCodeReuseAuditsEachFailedRevocation fails one of a revoking
// reuse's writes at a time: the first access token's revocation, the
// code grant's, or the GrantStore's revocation of the code grant's
// refresh tokens (storage.GrantRefreshTokenRevoker). Each alone is
// audited as a failed revocation, and the reuse still writes the
// others: the refresh token the code was exchanged for is revoked, and
// the first access token and the code grant are recorded as revoked
// unless their own write is the one failing.
func TestCodeReuseAuditsEachFailedRevocation(t *testing.T) {
	for name, f := range map[string]failedReuseRevocation{
		"access token revocation failing": {
			fail: func(s reuseRevocationStores, accessTokenKey string) {
				s.revocation.failing = func(key string) bool { return key == accessTokenKey }
			},
			codeGrant: true,
		},
		"code grant revocation failing": {
			fail:        func(s reuseRevocationStores, _ string) { s.revocation.failing = isCodeGrantKey },
			accessToken: true,
		},
		"grant refresh token revocation failing": {
			fail:        func(s reuseRevocationStores, _ string) { s.grants.down = true },
			accessToken: true, codeGrant: true,
		},
	} {
		t.Run(name, func(t *testing.T) { testCodeReuseWithAFailedRevocation(t, f) })
	}
}

// failedReuseRevocation is one of a revoking reuse's writes made to
// fail, and what the reuse records as revoked all the same.
type failedReuseRevocation struct {
	// fail makes the write fail in s, where the first access token is
	// revoked under accessTokenKey.
	fail func(s reuseRevocationStores, accessTokenKey string)

	// accessToken and codeGrant are whether the reuse records the first
	// access token and the code grant as revoked.
	accessToken, codeGrant bool
}

// testCodeReuseWithAFailedRevocation reuses a code with f's write
// failing: the reuse is refused and audited as a failed revocation, the
// code's refresh token is revoked, and the first access token and the
// code grant are recorded as revoked as f says.
func testCodeReuseWithAFailedRevocation(t *testing.T, f failedReuseRevocation) {
	s := newReuseRevocationStores(t)
	dpopKey := generateKey(t)
	code := completeSuccessfulAuthorization(t, s.h, []string{"openid", "accounts", "offline_access"})
	tokens, err := exchangeCode(t, s.h, code, dpopKey)
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	accessTokenKey := accessTokenJTI(t, s.h, tokens.AccessToken.Reveal())
	f.fail(s, accessTokenKey)
	audited := len(s.h.audit.all())
	_, err = exchangeCode(t, s.h, code, dpopKey)
	requireInvalidGrant(t, err)
	requireRevokingReuseAudited(t, s.h.audit.all()[audited:], server.AuditEvent{Outcome: server.AuditOutcomeFailure, Description: notAllRevoked})
	revoked := s.h.revocation.all()
	if slices.Contains(revoked, accessTokenKey) != f.accessToken || slices.ContainsFunc(revoked, isCodeGrantKey) != f.codeGrant {
		t.Errorf("revoked keys = %v, want the first access token's (%q) among them: %v, a code grant's: %v", revoked, accessTokenKey, f.accessToken, f.codeGrant)
	}
	if s.redeemable(tokens.RefreshToken.Reveal()) {
		t.Error("the GrantStore still redeems the refresh token the code was exchanged for")
	}
}

// isCodeGrantKey reports whether key is a code grant's revocation key
// (grantrevocation.CodeKey).
func isCodeGrantKey(key string) bool { return strings.HasPrefix(key, "code-grant:") }

// reuseRevocationStores is a harness whose stores can each fail one of
// the writes a revoking reuse makes: revocation's Revoke, for the keys
// its failing picks, and grants' RevokeGrantRefreshTokens, once down.
// grants is memstore's GrantStore, which records the tokens a code
// issued, as the harness's own does, and finds a grant's refresh
// tokens, which it doesn't.
type reuseRevocationStores struct {
	h          harness
	revocation *keyFailingRevocationSink
	grants     *failingGrantRevoker
}

func newReuseRevocationStores(t *testing.T) reuseRevocationStores {
	t.Helper()
	h := newHarness(t, server.ProfileFAPISecurity, true)
	s := reuseRevocationStores{
		revocation: &keyFailingRevocationSink{fakeRevocationSink: h.revocation},
		grants:     &failingGrantRevoker{GrantStore: memstore.NewGrantStore()},
	}
	s.h = withDependencies(t, h, func(d *server.Dependencies) {
		d.Revocation, d.Grants = s.revocation, s.grants
	})
	return s
}

// redeemable reports whether the GrantStore still redeems refreshToken.
func (s reuseRevocationStores) redeemable(refreshToken string) bool {
	_, err := s.grants.RedeemRefreshToken(context.Background(), storage.RefreshTokenRedemption{TokenHash: server.RefreshTokenHash(testIssuer, refreshToken)})
	return err == nil
}

// keyFailingRevocationSink is a fakeRevocationSink whose Revoke fails,
// recording nothing, for the keys failing picks, once it's set.
type keyFailingRevocationSink struct {
	*fakeRevocationSink
	failing func(key string) bool
}

func (s *keyFailingRevocationSink) Revoke(ctx context.Context, key string, expiresAt time.Time) error {
	if s.failing != nil && s.failing(key) {
		return errStoreDown
	}
	return s.fakeRevocationSink.Revoke(ctx, key, expiresAt)
}

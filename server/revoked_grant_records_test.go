package server_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// revokeWithAssertion revokes refreshToken at h's revocation endpoint,
// authenticated as testClientID with its client assertion.
func revokeWithAssertion(t *testing.T, h harness, refreshToken string) error {
	t.Helper()
	_, err := h.server.RevokeToken(context.Background(), server.TokenRevocationRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_assertion", h.clientAssertion(t)),
			formParam("client_assertion_type", clientassertion.AssertionType),
			formParam("token", refreshToken),
		}},
	})
	return err
}

// codeGrantRecords is when each code grant record in h's revocation
// store expires.
func codeGrantRecords(h harness) []time.Time {
	h.revocation.mu.Lock()
	defer h.revocation.mu.Unlock()
	var until []time.Time
	for key, expiresAt := range h.revocation.until {
		if strings.HasPrefix(key, "code-grant:") {
			until = append(until, expiresAt)
		}
	}
	return until
}

// TestRevokedRefreshTokensCodeGrantLastsAsLongAsRevokeGrants: revoking a
// refresh token from the authorization code flow — at the revocation
// endpoint, with RevokeListedGrant or with RevokeSubjectGrants — records
// its code grant as revoked for as long as RevokeGrant records a grant:
// 400 days, with the harness's minutes-long Limits.
func TestRevokedRefreshTokensCodeGrantLastsAsLongAsRevokeGrants(t *testing.T) {
	for name, revoke := range map[string]func(t *testing.T, h harness, owner *attestedInstance, refreshToken string) error{
		"RevokeToken": func(_ *testing.T, _ harness, owner *attestedInstance, refreshToken string) error {
			return owner.revoke(formParam("token", refreshToken))
		},
		"RevokeListedGrant": func(t *testing.T, h harness, _ *attestedInstance, _ string) error {
			return h.server.RevokeListedGrant(context.Background(), mustSubjectID(t, "user-1"), listGrants(t, h, "user-1")[0].ID)
		},
		"RevokeSubjectGrants": func(t *testing.T, h harness, _ *attestedInstance, _ string) error {
			_, err := h.server.RevokeSubjectGrants(context.Background(), mustSubjectID(t, "user-1"))
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			h, owner := registryHarness(t, memstore.NewGrantRegistry())
			if err := revoke(t, h, owner, owner.issueRefreshToken()); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if got, want := codeGrantRecords(h), h.now.Add(400*24*time.Hour); len(got) != 1 || !got[0].Equal(want) {
				t.Errorf("code grant records until %v, want one until %v", got, want)
			}
		})
	}
}

// TestRevokedRefreshTokensCodeGrantOutlastsALongerLifetime: a refresh
// token revoked at the revocation endpoint under a 1h lifetime, whose own
// revocation fails once its code grant is recorded as revoked, is
// refused by that record alone, here with the GrantStore failing to
// revoke it when a refresh presents it, too. The record must outlast the
// token once a 24h lifetime applies again, not lapse with a horizon
// sized from 1h.
func TestRevokedRefreshTokensCodeGrantOutlastsALongerLifetime(t *testing.T) {
	grants := &grantStoreOutage{GrantStore: memstore.NewGrantStore()}
	c := newLifetimeChanges(t, grants)
	refreshToken, _ := c.issueGrant("", 24*time.Hour)
	grants.down = true
	if err := revokeWithAssertion(t, c.at(time.Minute, time.Hour), refreshToken); err == nil || serverErrorCode(t, err) != server.ErrorServerError {
		t.Fatalf("RevokeToken, the refresh token's revocation failing = %v, want server_error", err)
	}
	if !c.stored(refreshToken) {
		t.Fatal("test setup: the refresh token was revoked though its revocation fails")
	}
	c.checkRefused(refreshToken, 3*time.Hour, 24*time.Hour-time.Second)
}

// revokingGrantStore is memstore's GrantStore that runs revoke, once, as
// CreateRefreshToken starts — a revocation of the grant landing after
// the token request has checked the grant but before its refresh token
// is stored, so that revoking the grant's refresh tokens misses it — and
// keeps the hash of each refresh token it creates. failRevoke, if set,
// is what RevokeRefreshToken returns.
type revokingGrantStore struct {
	*memstore.GrantStore
	revoke     func()
	created    [][32]byte
	failRevoke error
}

func (s *revokingGrantStore) CreateRefreshToken(ctx context.Context, token storage.NewRefreshToken) error {
	if revoke := s.revoke; revoke != nil {
		s.revoke = nil
		revoke()
	}
	s.created = append(s.created, token.TokenHash)
	return s.GrantStore.CreateRefreshToken(ctx, token)
}

func (s *revokingGrantStore) RevokeRefreshToken(ctx context.Context, tokenHash [32]byte) error {
	if s.failRevoke != nil {
		return s.failRevoke
	}
	return s.GrantStore.RevokeRefreshToken(ctx, tokenHash)
}

// redeemable reports whether grants still redeems the refresh token
// stored under tokenHash.
func redeemable(grants storage.GrantStore, tokenHash [32]byte) bool {
	_, err := grants.RedeemRefreshToken(context.Background(), storage.RefreshTokenRedemption{TokenHash: tokenHash})
	return err == nil
}

// exchangeRevokedMeanwhile exchanges a code for user-1's grant-1 on h,
// over grants, with RevokeGrant revoking grant-1 as the refresh token is
// about to be stored, and returns the exchange's error: one, since the
// grant is revoked.
func exchangeRevokedMeanwhile(t *testing.T, h harness, grants *revokingGrantStore) error {
	t.Helper()
	var revokeErr error
	grants.revoke = func() { revokeErr = h.server.RevokeGrant(context.Background(), "grant-1") }
	result, err := exchangeGrant(t, h, "grant-1")
	if revokeErr != nil {
		t.Fatalf("RevokeGrant mid-exchange: %v", revokeErr)
	}
	if err == nil {
		t.Fatalf("ExchangeAuthorizationCode, its grant revoked mid-exchange, succeeded (refresh token issued: %v), want it refused", result.HasRefreshToken)
	}
	return err
}

// TestRefreshTokenIsntIssuedForAGrantRevokedMeanwhile: RevokeGrant landing
// between a code exchange's check of the grant and the storage of its
// refresh token revokes the grant's refresh tokens before this one
// exists, so misses it. The exchange checks the grant again once the
// token is stored, and fails with server_error, withdrawing the token and
// deleting its registry entry, rather than issuing one only the grant's
// revocation record refuses, whether or not the GrantStore revokes a
// grant's refresh tokens itself. A withdrawal that fails is reported with
// it, and the token still isn't issued; it keeps its entry, by which
// RevokeSubjectGrants revokes it.
func TestRefreshTokenIsntIssuedForAGrantRevokedMeanwhile(t *testing.T) {
	for _, kind := range grantStoreKinds {
		t.Run(kind.name, func(t *testing.T) { testRevokedMeanwhile(t, kind) })
	}
	t.Run("withdrawal failing", testRevokedMeanwhileWithdrawalFailing)
}

// testRevokedMeanwhile runs exchangeRevokedMeanwhile over a GrantStore of
// kind, and checks the exchange fails with server_error, withdrawing the
// one refresh token it stored and deleting that token's entry alone, and
// lists nothing.
func testRevokedMeanwhile(t *testing.T, kind grantStoreKind) {
	grants := &revokingGrantStore{GrantStore: memstore.NewGrantStore()}
	c, deleted := newRecordedLifetimeChanges(t, kind.of(grants))
	h := c.at(0, 24*time.Hour)
	if err := exchangeRevokedMeanwhile(t, h, grants); serverErrorCode(t, err) != server.ErrorServerError {
		t.Fatalf("ExchangeAuthorizationCode, its grant revoked mid-exchange = %v, want server_error", err)
	}
	if len(grants.created) != 1 || redeemable(grants, grants.created[0]) {
		t.Fatalf("%d refresh tokens created, the first still redeemable; want the one created withdrawn", len(grants.created))
	}
	if want := server.GrantEntryKey(grants.created[0]); !slices.Equal(*deleted, []string{want}) {
		t.Errorf("DeleteGrant calls = %v, want the withdrawn refresh token's entry %s alone", *deleted, want)
	}
	if listed := listGrants(t, h, "user-1"); len(listed) != 0 {
		t.Errorf("ListGrants = %+v, want none: the grant is revoked", listed)
	}
}

// testRevokedMeanwhileWithdrawalFailing is exchangeRevokedMeanwhile with
// the withdrawal of the refresh token failing: the exchange reports both
// failures and issues nothing, and the token, still live in the store,
// keeps its registry entry, by which RevokeSubjectGrants revokes it once
// the store recovers.
func testRevokedMeanwhileWithdrawalFailing(t *testing.T) {
	grants := &revokingGrantStore{GrantStore: memstore.NewGrantStore(), failRevoke: errStoreDown}
	c, deleted := newRecordedLifetimeChanges(t, grants)
	h := c.at(0, 24*time.Hour)
	if err := exchangeRevokedMeanwhile(t, h, grants); serverErrorCode(t, err) != server.ErrorServerError || !errors.Is(err, errStoreDown) {
		t.Fatalf("ExchangeAuthorizationCode, its grant revoked mid-exchange and the withdrawal failing = %v, want server_error reporting both", err)
	}
	if len(*deleted) != 0 || len(grants.created) != 1 {
		t.Fatalf("DeleteGrant calls = %v, %d refresh tokens created; want the entry of the one created kept", *deleted, len(grants.created))
	}
	grants.failRevoke = nil
	if _, err := h.server.RevokeSubjectGrants(context.Background(), mustSubjectID(t, "user-1")); err != nil {
		t.Fatalf("RevokeSubjectGrants once the GrantStore recovered: %v", err)
	}
	if redeemable(grants, grants.created[0]) {
		t.Error("RevokeSubjectGrants left the refresh token the withdrawal failed to revoke redeemable")
	}
}

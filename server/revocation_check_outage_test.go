package server_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// revocationCheckOutage is an expiringRevocationStore whose IsRevoked
// fails with errStoreDown while down is set.
type revocationCheckOutage struct {
	*expiringRevocationStore
	down bool
}

func (s *revocationCheckOutage) IsRevoked(ctx context.Context, key string) (bool, error) {
	if s.down {
		return false, errStoreDown
	}
	return s.expiringRevocationStore.IsRevoked(ctx, key)
}

// grantBehindARevocationOutage issues user-1 a refresh token for
// grant-1, at the start under a 24h lifetime, over a revocation store
// that fails while its down is set, and returns the token and the
// grant's ListedGrant.ID.
func grantBehindARevocationOutage(t *testing.T) (c *lifetimeChanges, revocation *revocationCheckOutage, refreshToken, id string) {
	t.Helper()
	c = newLifetimeChanges(t, memstore.NewGrantStore())
	revocation = &revocationCheckOutage{expiringRevocationStore: &expiringRevocationStore{clock: c.clock}}
	c.h.deps.Revocation = revocation
	refreshToken, id = c.issueGrant("grant-1", 24*time.Hour)
	return c, revocation, refreshToken, id
}

// TestRefreshTokenIsntIssuedWhenItsGrantCantBeCheckedAgain: a code
// exchange whose grant passes the token request's revocation check, but
// whose revocation store fails once its refresh token is stored, when
// the issuance checks the grant again, fails closed, whether or not the
// GrantStore revokes a grant's refresh tokens itself: server_error,
// reporting the failure, with the refresh token withdrawn rather than
// issued unchecked, and its entry deleted, so the grant isn't listed as
// connected once the store recovers.
func TestRefreshTokenIsntIssuedWhenItsGrantCantBeCheckedAgain(t *testing.T) {
	for _, kind := range grantStoreKinds {
		t.Run(kind.name, func(t *testing.T) { testRecheckOutage(t, kind) })
	}
}

// testRecheckOutage runs a code exchange over a GrantStore of kind whose
// revocation store goes down as the refresh token is stored, and checks
// the exchange issues nothing.
func testRecheckOutage(t *testing.T, kind grantStoreKind) {
	grants := &revokingGrantStore{GrantStore: memstore.NewGrantStore()}
	c := newLifetimeChanges(t, kind.of(grants))
	revocation := &revocationCheckOutage{expiringRevocationStore: &expiringRevocationStore{clock: c.clock}}
	c.h.deps.Revocation = revocation
	grants.revoke = func() { revocation.down = true }
	h := c.at(0, 24*time.Hour)

	result, err := exchangeGrant(t, h, "grant-1")
	if err == nil || serverErrorCode(t, err) != server.ErrorServerError || !errors.Is(err, errStoreDown) {
		t.Fatalf("ExchangeAuthorizationCode, the revocation store failing once the refresh token is stored = %v, want server_error reporting the failure", err)
	}
	if result.HasRefreshToken || result.RefreshToken.Reveal() != "" {
		t.Error("the failed exchange returned a refresh token")
	}
	if len(grants.created) != 1 || redeemable(grants, grants.created[0]) {
		t.Errorf("%d refresh tokens created, the first still redeemable; want the one created withdrawn", len(grants.created))
	}
	revocation.down = false
	if listed := listGrants(t, h, "user-1"); len(listed) != 0 {
		t.Errorf("ListGrants once the revocation store recovered = %+v, want none: the grant's refresh token was never issued", listed)
	}
}

// TestRefreshKeepsTheTokenWhenItsGrantCantBeChecked: a refresh whose
// grant's revocation can't be checked is answered server_error and
// leaves the refresh token, and its grant's entry, alone, for the client
// to refresh with once the revocation store recovers: only a grant found
// revoked has its refresh token revoked when a refresh presents it.
func TestRefreshKeepsTheTokenWhenItsGrantCantBeChecked(t *testing.T) {
	c, revocation, refreshToken, id := grantBehindARevocationOutage(t)
	h := c.at(time.Minute, 24*time.Hour)

	revocation.down = true
	if _, err := refreshWith(t, h, refreshToken, ""); err == nil || serverErrorCode(t, err) != server.ErrorServerError {
		t.Fatalf("refresh, the grant's revocation unreadable = %v, want server_error", err)
	}
	revocation.down = false
	if _, err := refreshWith(t, h, refreshToken, ""); err != nil {
		t.Fatalf("refresh once the revocation store recovered = %v, want the refresh token still live", err)
	}
	checkListedUntil(t, h, id, c.start.Add(24*time.Hour))
}

// TestGrantListingReportsAGrantWhoseRevocationCantBeChecked: a registry
// entry whose grant's revocation can't be checked is unreadable, neither
// listed nor taken for a grant revoked another way. ListGrants,
// RevokeListedGrant and RevokeSubjectGrants report the failure, and none
// revokes the grant's refresh token as a revoked grant's: an outage of
// the revocation store ends no grant.
func TestGrantListingReportsAGrantWhoseRevocationCantBeChecked(t *testing.T) {
	ctx := context.Background()
	subject := mustSubjectID(t, "user-1")
	c, revocation, refreshToken, id := grantBehindARevocationOutage(t)
	h := c.at(time.Minute, 24*time.Hour)

	revocation.down = true
	if _, err := h.server.ListGrants(ctx, subject); !errors.Is(err, errStoreDown) {
		t.Errorf("ListGrants, the revocation store down = %v, want the failure", err)
	}
	if err := h.server.RevokeListedGrant(ctx, subject, id); !errors.Is(err, errStoreDown) {
		t.Errorf("RevokeListedGrant, the revocation store down = %v, want the failure", err)
	}
	if n, err := h.server.RevokeSubjectGrants(ctx, subject); n != 0 || !errors.Is(err, errStoreDown) {
		t.Errorf("RevokeSubjectGrants, the revocation store down = %d, %v; want 0 and the failure", n, err)
	}
	if !c.stored(refreshToken) {
		t.Error("the refresh token was revoked though its grant's revocation couldn't be checked")
	}
	revocation.down = false
	checkListedUntil(t, h, id, c.start.Add(24*time.Hour))
}

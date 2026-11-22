package server_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// longRefreshLifetime is a refresh token lifetime past the 400 days a
// revoked grant's revocation record lasts at least.
const longRefreshLifetime = 500 * 24 * time.Hour

// pastTheRecord is long enough after a revocation a minute in for the
// grant's revocation record, which lasts 400 days with the harness's
// Limits, to have lapsed: under longRefreshLifetime, nothing but the
// GrantStore then refuses the grant's refresh token.
const pastTheRecord = 400*24*time.Hour + 2*time.Minute

// grantStoreOutage is memstore's GrantStore whose revocations fail with
// errStoreDown: every one, of a grant's refresh tokens or of one, while
// down is set, and RevokeRefreshToken of the refresh tokens in
// downTokens.
type grantStoreOutage struct {
	*memstore.GrantStore
	down       bool
	downTokens map[[32]byte]bool
}

func (s *grantStoreOutage) RevokeGrantRefreshTokens(ctx context.Context, grantKey string) ([][32]byte, error) {
	if s.down {
		return nil, errStoreDown
	}
	return s.GrantStore.RevokeGrantRefreshTokens(ctx, grantKey)
}

func (s *grantStoreOutage) RevokeRefreshToken(ctx context.Context, tokenHash [32]byte) error {
	if s.down || s.downTokens[tokenHash] {
		return errStoreDown
	}
	return s.GrantStore.RevokeRefreshToken(ctx, tokenHash)
}

// newRecordedLifetimeChanges is newLifetimeChanges over grants, with a
// GrantRegistry recording the keys DeleteGrant is called with.
func newRecordedLifetimeChanges(t *testing.T, grants storage.GrantStore) (*lifetimeChanges, *[]string) {
	t.Helper()
	c := newLifetimeChanges(t, grants)
	deleted := new([]string)
	c.h.deps.GrantRegistry = deleteRecordingRegistry{memstore.NewGrantRegistry(), deleted}
	return c, deleted
}

// issueGrant issues user-1 a refresh token at the start, under
// refreshLifetime, for a grant named grantID, and returns the token and
// the grant's ListedGrant.ID.
func (c *lifetimeChanges) issueGrant(grantID string, refreshLifetime time.Duration) (refreshToken, id string) {
	c.t.Helper()
	refreshToken = exchangeWithGrantID(c.t, c.at(0, refreshLifetime), grantID)
	return refreshToken, server.GrantEntryKey(sha256.Sum256([]byte(refreshToken)))
}

// revokeGrantAt revokes grantID a minute in, under a 1h refresh token
// lifetime, and returns the server that did.
func (c *lifetimeChanges) revokeGrantAt(grantIDs ...string) harness {
	c.t.Helper()
	h := c.at(time.Minute, time.Hour)
	for _, grantID := range grantIDs {
		if err := h.server.RevokeGrant(context.Background(), grantID); err != nil {
			c.t.Fatalf("RevokeGrant(%s): %v", grantID, err)
		}
	}
	return h
}

// checkSwept checks that the GrantStore no longer redeems refreshToken,
// and that its grant's entry, id, was deleted.
func (c *lifetimeChanges) checkSwept(refreshToken, id string, deleted []string) {
	c.t.Helper()
	if c.stored(refreshToken) {
		c.t.Errorf("the GrantStore still holds the refresh token of grant %s", id)
	}
	if !slices.Contains(deleted, id) {
		c.t.Errorf("DeleteGrant calls = %v, want the grant's entry %s", deleted, id)
	}
}

// checkRecordLapsed moves the clock to pastTheRecord and checks that
// grantID's revocation record has lapsed there, so the GrantStore alone
// decides whether its refresh token is redeemed.
func (c *lifetimeChanges) checkRecordLapsed(grantID string) {
	c.t.Helper()
	c.clock.set(c.start.Add(pastTheRecord))
	revoked, err := c.h.deps.Revocation.(*expiringRevocationStore).IsRevoked(context.Background(), "grant:"+grantID+"@"+testIssuer)
	if err != nil || revoked {
		c.t.Fatalf("test setup: %s's revocation record %v on: revoked %v, %v; want it lapsed", grantID, pastTheRecord, revoked, err)
	}
}

// TestRevokeSubjectGrantsEndsRevokedGrantsRefreshTokens: RevokeSubjectGrants
// revokes the refresh token of a grant RevokeGrant revoked, and deletes
// its entry, without counting it, whether the GrantStore revoked the
// token already or, without storage.GrantRefreshTokenRevoker, still holds
// it: nothing redeems the token once the grant's 400-day record has
// lapsed, under a 500-day refresh token lifetime.
func TestRevokeSubjectGrantsEndsRevokedGrantsRefreshTokens(t *testing.T) {
	for _, kind := range grantStoreKinds {
		t.Run(kind.name, func(t *testing.T) {
			c, deleted := newRecordedLifetimeChanges(t, kind.of(memstore.NewGrantStore()))
			refreshToken, id := c.issueGrant("grant-1", longRefreshLifetime)
			h := c.revokeGrantAt("grant-1")
			c.checkStored(kind, refreshToken, "RevokeGrant")
			if n, err := h.server.RevokeSubjectGrants(context.Background(), mustSubjectID(t, "user-1")); n != 0 || err != nil {
				t.Fatalf("RevokeSubjectGrants after RevokeGrant = %d, %v; want 0, nil: the grant was revoked already", n, err)
			}
			c.checkSwept(refreshToken, id, *deleted)
			c.checkRecordLapsed("grant-1")
			c.checkRefusedUnder(longRefreshLifetime, refreshToken, pastTheRecord)
		})
	}
}

// TestRevokeListedGrantEndsRevokedGrantsRefreshTokens: RevokeListedGrant
// revokes the refresh tokens of the user's grants RevokeGrant revoked,
// and deletes their entries, answering as before: ErrGrantNotListed for
// an ID naming one of them, and nil once it has revoked the listed grant
// an ID names.
func TestRevokeListedGrantEndsRevokedGrantsRefreshTokens(t *testing.T) {
	for _, kind := range grantStoreKinds {
		t.Run(kind.name, func(t *testing.T) { testRevokeListedGrantSweeps(t, kind) })
	}
}

func testRevokeListedGrantSweeps(t *testing.T, kind grantStoreKind) {
	ctx := context.Background()
	subject := mustSubjectID(t, "user-1")
	c, deleted := newRecordedLifetimeChanges(t, kind.of(memstore.NewGrantStore()))
	first, firstID := c.issueGrant("grant-1", longRefreshLifetime)
	second, secondID := c.issueGrant("grant-2", longRefreshLifetime)
	listed, listedID := c.issueGrant("grant-3", longRefreshLifetime)

	h := c.revokeGrantAt("grant-1")
	if err := h.server.RevokeListedGrant(ctx, subject, firstID); !errors.Is(err, server.ErrGrantNotListed) {
		t.Fatalf("RevokeListedGrant(a grant RevokeGrant revoked) = %v, want ErrGrantNotListed", err)
	}
	c.checkSwept(first, firstID, *deleted)

	h = c.revokeGrantAt("grant-2")
	if err := h.server.RevokeListedGrant(ctx, subject, listedID); err != nil {
		t.Fatalf("RevokeListedGrant(a listed grant) = %v, want nil", err)
	}
	c.checkSwept(second, secondID, *deleted)
	c.checkSwept(listed, listedID, *deleted)
	c.checkRecordLapsed("grant-1")
	c.checkRefusedUnder(longRefreshLifetime, first, pastTheRecord)
	c.checkRefusedUnder(longRefreshLifetime, second, pastTheRecord)
	c.checkRefusedUnder(longRefreshLifetime, listed, pastTheRecord)
}

// TestRevokedGrantsSweepReportsFailures: a failure to revoke a revoked
// grant's refresh token, or to delete its entry once the token is
// revoked, leaves the entry for a later call. RevokeSubjectGrants
// reports it, as RevokeListedGrant does for an ID naming no listed grant,
// which may be that grant's, but not when it revokes the listed grant an
// ID names: the others' are best effort then. Once the stores recover, a
// call finishes the job.
func TestRevokedGrantsSweepReportsFailures(t *testing.T) {
	t.Run("GrantStore", testSweepWithTheGrantStoreFailing)
	t.Run("GrantRegistry", testSweepWithTheGrantRegistryFailing)
	t.Run("beside a listed grant", testSweepBesideAListedGrant)
}

func testSweepWithTheGrantStoreFailing(t *testing.T) {
	ctx := context.Background()
	subject := mustSubjectID(t, "user-1")
	grants := &grantStoreOutage{GrantStore: memstore.NewGrantStore()}
	c, deleted := newRecordedLifetimeChanges(t, grantStoreOnly{grants})
	refreshToken, id := c.issueGrant("grant-1", longRefreshLifetime)
	h := c.revokeGrantAt("grant-1")

	grants.down = true
	if n, err := h.server.RevokeSubjectGrants(ctx, subject); n != 0 || !errors.Is(err, errStoreDown) {
		t.Fatalf("RevokeSubjectGrants, the refresh token's revocation failing = %d, %v; want 0 and the failure", n, err)
	}
	for _, named := range []string{id, "another-id"} {
		if err := h.server.RevokeListedGrant(ctx, subject, named); !errors.Is(err, errStoreDown) || errors.Is(err, server.ErrGrantNotListed) {
			t.Fatalf("RevokeListedGrant(%s), the refresh token's revocation failing = %v, want the failure", named, err)
		}
	}
	if len(*deleted) != 0 || !c.stored(refreshToken) {
		t.Fatalf("after the failures, DeleteGrant calls = %v, and the refresh token stored: %v; want the entry kept for a retry", *deleted, c.stored(refreshToken))
	}

	grants.down = false
	if err := h.server.RevokeListedGrant(ctx, subject, id); !errors.Is(err, server.ErrGrantNotListed) {
		t.Fatalf("RevokeListedGrant once the GrantStore recovered = %v, want ErrGrantNotListed", err)
	}
	c.checkSwept(refreshToken, id, *deleted)
	if n, err := h.server.RevokeSubjectGrants(ctx, subject); n != 0 || err != nil {
		t.Fatalf("RevokeSubjectGrants after = %d, %v; want 0, nil", n, err)
	}
}

func testSweepWithTheGrantRegistryFailing(t *testing.T) {
	ctx := context.Background()
	subject := mustSubjectID(t, "user-1")
	c := newLifetimeChanges(t, grantStoreOnly{memstore.NewGrantStore()})
	registry := &recoveringRegistry{GrantRegistry: memstore.NewGrantRegistry()}
	c.h.deps.GrantRegistry = registry
	refreshToken, _ := c.issueGrant("grant-1", longRefreshLifetime)
	h := c.revokeGrantAt("grant-1")

	registry.down = true
	if n, err := h.server.RevokeSubjectGrants(ctx, subject); n != 0 || err == nil || !strings.Contains(err.Error(), "registry down") {
		t.Fatalf("RevokeSubjectGrants, the entry's deletion failing = %d, %v; want 0 and the failure", n, err)
	}
	if c.stored(refreshToken) {
		t.Error("the refresh token wasn't revoked before its entry's deletion failed")
	}
	registry.down = false
	if n, err := h.server.RevokeSubjectGrants(ctx, subject); n != 0 || err != nil {
		t.Fatalf("RevokeSubjectGrants once the GrantRegistry recovered = %d, %v; want 0, nil", n, err)
	}
	// The entry is gone, so a registry failing to delete it is no longer
	// asked to.
	registry.down = true
	if n, err := h.server.RevokeSubjectGrants(ctx, subject); n != 0 || err != nil {
		t.Fatalf("RevokeSubjectGrants with nothing left to delete = %d, %v; want 0, nil", n, err)
	}
}

func testSweepBesideAListedGrant(t *testing.T) {
	grants := &grantStoreOutage{GrantStore: memstore.NewGrantStore()}
	c := newLifetimeChanges(t, grantStoreOnly{grants})
	revoked, _ := c.issueGrant("grant-1", longRefreshLifetime)
	listed, listedID := c.issueGrant("grant-2", longRefreshLifetime)
	h := c.revokeGrantAt("grant-1")
	grants.downTokens = map[[32]byte]bool{sha256.Sum256([]byte(revoked)): true}
	if err := h.server.RevokeListedGrant(context.Background(), mustSubjectID(t, "user-1"), listedID); err != nil {
		t.Fatalf("RevokeListedGrant(a listed grant), a revoked grant's refresh token failing to revoke = %v, want nil", err)
	}
	if c.stored(listed) {
		t.Error("the listed grant's refresh token is still stored")
	}
	if !c.stored(revoked) {
		t.Error("test setup: the revoked grant's refresh token was revoked though its revocation fails")
	}
}

// TestRevokedGrantsSweepRefusesAnEntryWithoutItsToken: an entry of a
// grant revoked another way whose refresh token hash isn't the one its
// key is derived from — another token's, as a forged unsealed record's
// could be — isn't swept: RevokeSubjectGrants and RevokeListedGrant
// revoke no refresh token by it and leave it, as they revoke nothing by
// such an entry of a grant that isn't revoked
// (TestRevokeListedGrantRefusesAnEntryWithoutItsToken).
func TestRevokedGrantsSweepRefusesAnEntryWithoutItsToken(t *testing.T) {
	ctx := context.Background()
	subject := mustSubjectID(t, "user-1")
	registry := &stubRegistry{}
	h := stubRegistryHarness(t, registry)
	other := sha256.Sum256([]byte("other"))
	registry.entries = []storage.GrantEntry{registryEntry(t, h, "k", testIssuer, "user-1", h.now, map[string]any{"rth": other[:], "grant_id": "grant-1"})}
	if err := h.server.RevokeGrant(ctx, "grant-1"); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}
	if n, err := h.server.RevokeSubjectGrants(ctx, subject); n != 0 || err != nil {
		t.Errorf("RevokeSubjectGrants = %d, %v; want 0, nil", n, err)
	}
	if err := h.server.RevokeListedGrant(ctx, subject, registryKey("k")); !errors.Is(err, server.ErrGrantNotListed) {
		t.Errorf("RevokeListedGrant(the mismatched entry) = %v, want ErrGrantNotListed", err)
	}
	h.grants.mu.Lock()
	revoked := h.grants.refreshRevoked[other]
	h.grants.mu.Unlock()
	if revoked || len(registry.deleted) != 0 {
		t.Errorf("the refresh token the entry names revoked: %v, DeleteGrant calls %v; want neither", revoked, registry.deleted)
	}
}

// failedRevokeGrant is an outage that makes RevokeGrant fail once it has
// recorded the grant as revoked.
type failedRevokeGrant struct {
	name string

	// stores is the GrantStore and GrantRegistry the outage is in, and
	// down starts or ends it.
	stores func() (storage.GrantStore, storage.GrantRegistry, func(down bool))

	// failure is in RevokeGrant's error, and isOutage reports whether an
	// error is the outage's.
	failure  string
	isOutage func(error) bool
}

var failedRevokeGrants = []failedRevokeGrant{
	{
		name: "GrantStore",
		stores: func() (storage.GrantStore, storage.GrantRegistry, func(bool)) {
			grants := &grantStoreOutage{GrantStore: memstore.NewGrantStore()}
			return grants, memstore.NewGrantRegistry(), func(down bool) { grants.down = down }
		},
		failure:  "the grant is revoked, but its refresh tokens couldn't all be revoked",
		isOutage: func(err error) bool { return errors.Is(err, errStoreDown) },
	},
	{
		name: "GrantRegistry",
		stores: func() (storage.GrantStore, storage.GrantRegistry, func(bool)) {
			registry := &recoveringRegistry{GrantRegistry: memstore.NewGrantRegistry()}
			return memstore.NewGrantStore(), registry, func(down bool) { registry.down = down }
		},
		failure:  "the grant and its refresh tokens are revoked, but some of their grant registry entries couldn't be removed",
		isOutage: func(err error) bool { return err != nil && strings.Contains(err.Error(), "registry down") },
	},
}

// TestRevokingGrantsAgainFinishesAFailedRevokeGrant: RevokeSubjectGrants
// or RevokeListedGrant revoking a grant whose RevokeGrant records the
// grant as revoked, then fails on its refresh tokens or their entries,
// reports the failure, and the grant is no longer listed. Calling it
// again still reaches the grant's refresh token: while the outage lasts
// it reports the failure again, rather than nothing left to do, and once
// the stores have recovered it finishes the job, so nothing redeems the
// token once the grant's record has lapsed.
func TestRevokingGrantsAgainFinishesAFailedRevokeGrant(t *testing.T) {
	revocations := map[string]func(h harness, subject server.SubjectID, id string) error{
		"RevokeSubjectGrants": func(h harness, subject server.SubjectID, _ string) error {
			n, err := h.server.RevokeSubjectGrants(context.Background(), subject)
			if n != 0 {
				return fmt.Errorf("revoked %d grants, want none counted, the first failing (%v)", n, err)
			}
			return err
		},
		"RevokeListedGrant": func(h harness, subject server.SubjectID, id string) error {
			// Once the job's finished, the grant isn't listed.
			if err := h.server.RevokeListedGrant(context.Background(), subject, id); !errors.Is(err, server.ErrGrantNotListed) {
				return err
			}
			return nil
		},
	}
	for _, outage := range failedRevokeGrants {
		for name, revoke := range revocations {
			t.Run(outage.name+"/"+name, func(t *testing.T) { testFailedRevokeGrantFinished(t, outage, revoke) })
		}
	}
}

func testFailedRevokeGrantFinished(t *testing.T, outage failedRevokeGrant, revoke func(harness, server.SubjectID, string) error) {
	subject := mustSubjectID(t, "user-1")
	grants, registry, setDown := outage.stores()
	c := newLifetimeChanges(t, grants)
	c.h.deps.GrantRegistry = registry
	refreshToken, id := c.issueGrant("grant-1", longRefreshLifetime)
	h := c.at(time.Minute, time.Hour)

	setDown(true)
	if err := revoke(h, subject, id); !outage.isOutage(err) || !strings.Contains(err.Error(), outage.failure) {
		t.Fatalf("revoking, RevokeGrant failing = %v, want its failure: %s", err, outage.failure)
	}
	if listed := listGrants(t, h, "user-1"); len(listed) != 0 {
		t.Fatalf("test setup: ListGrants = %+v, want none: the grant is recorded as revoked", listed)
	}
	if err := revoke(h, subject, id); !outage.isOutage(err) {
		t.Fatalf("revoking again, the outage lasting = %v, want the failure reported again", err)
	}
	setDown(false)
	if err := revoke(h, subject, id); err != nil {
		t.Fatalf("revoking again, the stores recovered = %v, want the job finished", err)
	}
	// The entry is gone: an outage now finds nothing left to do.
	setDown(true)
	if err := revoke(h, subject, id); err != nil {
		t.Fatalf("revoking once the job is finished, during an outage = %v, want nothing left to do", err)
	}
	setDown(false)
	if c.stored(refreshToken) {
		t.Error("the refresh token is still stored")
	}
	c.checkRecordLapsed("grant-1")
	c.checkRefusedUnder(longRefreshLifetime, refreshToken, pastTheRecord)
}

// checkListedUntil checks that h lists user-1's grant id alone, expiring
// at expiresAt.
func checkListedUntil(t *testing.T, h harness, id string, expiresAt time.Time) {
	t.Helper()
	grants := listGrants(t, h, "user-1")
	if len(grants) != 1 || grants[0].ID != id || !grants[0].ExpiresAt.Equal(expiresAt) {
		t.Fatalf("ListGrants = %+v, want %s alone, expiring at %v", grants, id, expiresAt)
	}
}

// TestListGrantsJudgesExpiryByTheCurrentRefreshLifetime: a grant whose
// refresh token was issued longer ago than the current
// Limits.RefreshTokenLifetime isn't listed, as a refresh refuses the
// token as expired, and a listed grant expires by the current lifetime
// when that's sooner than its stored expiry. A longer lifetime applying
// again lists the grant again, with its stored expiry.
func TestListGrantsJudgesExpiryByTheCurrentRefreshLifetime(t *testing.T) {
	c := newLifetimeChanges(t, memstore.NewGrantStore())
	refreshToken, id := c.issueGrant("grant-1", 24*time.Hour)
	checkListedUntil(t, c.at(30*time.Minute, time.Hour), id, c.start.Add(time.Hour))

	h := c.at(2*time.Hour, time.Hour)
	if grants := listGrants(t, h, "user-1"); len(grants) != 0 {
		t.Errorf("ListGrants 2h on, under 1h = %+v, want none: the refresh token was issued more than 1h before", grants)
	}
	if _, err := refreshWith(t, h, refreshToken, ""); err == nil || serverErrorDescription(t, err) != "refresh_token has expired" {
		t.Fatalf("refresh 2h on, under 1h = %v, want it refused as expired", err)
	}
	checkListedUntil(t, c.at(3*time.Hour, 24*time.Hour), id, c.start.Add(24*time.Hour))
}

// TestGrantsPastTheCurrentRefreshLifetimeAreStillRevoked: RevokeSubjectGrants,
// and RevokeListedGrant with the ID ListGrants gave earlier, revoke a
// grant ListGrants no longer lists only because its refresh token was
// issued longer ago than the current lifetime: a longer lifetime applying
// again would make the token redeemable, so it's revoked, not skipped.
func TestGrantsPastTheCurrentRefreshLifetimeAreStillRevoked(t *testing.T) {
	ctx := context.Background()
	for name, revoke := range map[string]func(h harness, subject server.SubjectID, id string) error{
		"RevokeSubjectGrants": func(h harness, subject server.SubjectID, _ string) error {
			if n, err := h.server.RevokeSubjectGrants(ctx, subject); err != nil || n != 1 {
				return fmt.Errorf("revoked %d grants, want 1 (%v)", n, err)
			}
			return nil
		},
		"RevokeListedGrant": func(h harness, subject server.SubjectID, id string) error {
			return h.server.RevokeListedGrant(ctx, subject, id)
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := newLifetimeChanges(t, memstore.NewGrantStore())
			refreshToken, id := c.issueGrant("", 24*time.Hour)
			if err := revoke(c.at(2*time.Hour, time.Hour), mustSubjectID(t, "user-1"), id); err != nil {
				t.Fatalf("%s 2h on, under 1h: %v", name, err)
			}
			c.checkRefused(refreshToken, 3*time.Hour, 24*time.Hour-time.Second)
		})
	}
}

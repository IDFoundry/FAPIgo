package server_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// A RevokeSubjectGrants that lists a grant after IssueRefreshToken has
// recorded it, and revokes its refresh token before the token is
// stored, on a GrantStore that keeps that revocation (a tombstone) and
// on one that forgets it (fakeGrantStore.noTombstones): either way the
// token never ends up live. Without the tombstone the server's own
// checks carry it: the issuance's confirmation that its entry is still
// recorded, and the revocation's second revocation of the token after
// deleting the entry.

// revocationOrderKey marks the context of the revocation's store calls,
// so the ordering wrappers below tell them from the issuance's.
type revocationOrderKey struct{}

func isRevocation(ctx context.Context) bool { return ctx.Value(revocationOrderKey{}) != nil }

// revocationOrder orders an issuance's and a revocation's store calls.
// recorded is closed once the issuance has recorded its grant;
// firstRevoked once the revocation's first RevokeRefreshToken has
// returned; revocationDone once the revocation has returned; confirmed
// once the issuance has listed its own entry, to confirm it. The
// issuance's CreateRefreshToken waits for createAfter (firstRevoked or
// revocationDone), and with holdDelete the revocation's DeleteGrant
// waits for confirmed.
type revocationOrder struct {
	recorded, firstRevoked, revocationDone, confirmed chan struct{}
	createAfter                                       chan struct{}
	recordOnce, firstRevokedOnce, confirmOnce         sync.Once
	holdDelete                                        bool
	timeout                                           <-chan time.Time
}

func newRevocationOrder(holdDelete bool) *revocationOrder {
	o := &revocationOrder{
		recorded: make(chan struct{}), firstRevoked: make(chan struct{}), revocationDone: make(chan struct{}), confirmed: make(chan struct{}),
		holdDelete: holdDelete, timeout: time.After(30 * time.Second),
	}
	o.createAfter = o.revocationDone
	if holdDelete {
		o.createAfter = o.firstRevoked
	}
	return o
}

// wait waits for ch, or until o's timeout, so a schedule that can't be
// met fails rather than hangs.
func (o *revocationOrder) wait(ch chan struct{}) {
	select {
	case <-ch:
	case <-o.timeout:
	}
}

// orderedGrants is a fakeGrantStore whose issuance's CreateRefreshToken
// waits for its revocationOrder's createAfter.
type orderedGrants struct {
	*fakeGrantStore
	order *revocationOrder
}

func (g orderedGrants) CreateRefreshToken(ctx context.Context, tok storage.NewRefreshToken) error {
	if !isRevocation(ctx) {
		g.order.wait(g.order.createAfter)
	}
	return g.fakeGrantStore.CreateRefreshToken(ctx, tok)
}

func (g orderedGrants) RevokeRefreshToken(ctx context.Context, tokenHash [32]byte) error {
	err := g.fakeGrantStore.RevokeRefreshToken(ctx, tokenHash)
	if isRevocation(ctx) {
		g.order.firstRevokedOnce.Do(func() { close(g.order.firstRevoked) })
	}
	return err
}

// orderedRegistry is a GrantRegistry whose DeleteGrant, with
// holdDelete, waits for the issuance to have confirmed its entry.
type orderedRegistry struct {
	*memstore.GrantRegistry
	order *revocationOrder
}

func (r orderedRegistry) RecordGrant(ctx context.Context, entry storage.NewGrantEntry) error {
	err := r.GrantRegistry.RecordGrant(ctx, entry)
	r.order.recordOnce.Do(func() { close(r.order.recorded) })
	return err
}

func (r orderedRegistry) ListGrants(ctx context.Context, listing storage.GrantListing) ([]storage.GrantEntry, error) {
	entries, err := r.GrantRegistry.ListGrants(ctx, listing)
	if !isRevocation(ctx) && listing.Key != "" {
		r.order.confirmOnce.Do(func() { close(r.order.confirmed) })
	}
	return entries, err
}

func (r orderedRegistry) DeleteGrant(ctx context.Context, key string) error {
	if r.order.holdDelete && isRevocation(ctx) {
		r.order.wait(r.order.confirmed)
	}
	return r.GrantRegistry.DeleteGrant(ctx, key)
}

// TestGrantRevokedBeforeItsTokenIsStored runs RevokeSubjectGrants once
// IssueRefreshToken has recorded its grant, its first revocation of the
// refresh token before the token is stored, in two orders:
//
//   - "deleted before the confirmation": the revocation finishes before
//     the token is stored, so the issuance finds its entry gone and
//     withdraws the token, refusing the issuance.
//   - "deleted after the confirmation": the issuance stores the token
//     and confirms its entry before the revocation deletes it, so it
//     issues the token, and the revocation's second revocation, after
//     the deletion, is what ends it on a store without tombstones.
//
// In both the revocation counts the grant, and no refresh token created
// is live once both have returned.
func TestGrantRevokedBeforeItsTokenIsStored(t *testing.T) {
	for kind, noTombstones := range tombstoneKinds {
		for name, holdDelete := range map[string]bool{"deleted before the confirmation": false, "deleted after the confirmation": true} {
			t.Run(kind+"/"+name, func(t *testing.T) {
				order := newRevocationOrder(holdDelete)
				h, owner := registryHarness(t, orderedRegistry{memstore.NewGrantRegistry(), order}, func(deps *server.Dependencies) {
					deps.Grants = orderedGrants{deps.Grants.(*fakeGrantStore), order}
				})
				h.grants.noTombstones = noTombstones
				before := len(h.grants.refreshTokens)
				issueErr, revoked, revokeErr := raceRevocationWithIssuance(t, h, owner, order)
				if revoked != 1 || revokeErr != nil {
					t.Fatalf("RevokeSubjectGrants = %d, %v, want 1, nil", revoked, revokeErr)
				}
				if holdDelete == (issueErr != nil) {
					t.Fatalf("IssueRefreshToken = %v, want it refused only when the entry was deleted before its confirmation", issueErr)
				}
				checkNoLiveRefreshTokenSince(t, h, before)
			})
		}
	}
}

// raceRevocationWithIssuance runs IssueRefreshToken for holder-1 on h,
// and RevokeSubjectGrants of holder-1 once the issuance has recorded
// its grant, returning their outcomes once both have returned.
func raceRevocationWithIssuance(t *testing.T, h harness, owner *attestedInstance, order *revocationOrder) (issueErr error, revoked int, revokeErr error) {
	t.Helper()
	attested, binding := embedderTokenRequest(t, owner)
	subject := mustSubjectID(t, "holder-1")
	var wg sync.WaitGroup
	wg.Go(func() {
		_, issueErr = h.server.IssueRefreshToken(context.Background(), server.IssueRefreshTokenRequest{
			GrantType: preAuthorizedCodeGrant, Client: attested, Binding: binding,
			Subject: subject, Scope: []string{"accounts"},
		})
	})
	wg.Go(func() {
		defer close(order.revocationDone)
		order.wait(order.recorded)
		revoked, revokeErr = h.server.RevokeSubjectGrants(context.WithValue(context.Background(), revocationOrderKey{}, true), subject)
	})
	wg.Wait()
	return issueErr, revoked, revokeErr
}

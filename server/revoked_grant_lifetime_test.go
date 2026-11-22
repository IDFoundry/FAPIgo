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

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// grantStoreKind is one of the two kinds of GrantStore the tests below
// run over: memstore's, which revokes a revoked grant's refresh tokens
// itself (storage.GrantRefreshTokenRevoker), or, recordOnly, the same
// store behind grantStoreOnly, as a GrantStore without that is, whose
// revoked grants' refresh tokens stay stored and only the grants'
// revocation records refuse.
type grantStoreKind struct {
	name       string
	recordOnly bool
}

var grantStoreKinds = []grantStoreKind{{"revokes refresh tokens", false}, {"record only", true}}

// of is store as a GrantStore of kind k.
func (k grantStoreKind) of(store storage.GrantStore) storage.GrantStore {
	if k.recordOnly {
		return grantStoreOnly{store}
	}
	return store
}

// grantStoreOnly shows only its GrantStore's GrantStore methods, hiding
// any optional interface the store implements.
type grantStoreOnly struct{ storage.GrantStore }

// unrecordedGrantStore records nothing in RecordIssuedAccessToken and
// RecordIssuedRefreshToken, as GrantStore's contract allows: a reuse of
// a code then can't revoke what the code issued by the tokens' own keys,
// only through the code's grant.
type unrecordedGrantStore struct{ *memstore.GrantStore }

func (unrecordedGrantStore) RecordIssuedAccessToken(context.Context, [32]byte, string, time.Time) error {
	return nil
}

func (unrecordedGrantStore) RecordIssuedRefreshToken(context.Context, [32]byte, [32]byte, time.Time) error {
	return nil
}

// lifetimeChanges is a server over one set of stores — grants, a
// GrantRegistry, and a revocation store that forgets a record once it
// expires — rebuilt at a time on a settableClock with the
// Limits.RefreshTokenLifetime it's asked for, as an operator changing
// the lifetime and restarting, or instances with different Limits
// sharing the stores, would.
type lifetimeChanges struct {
	t     *testing.T
	start time.Time
	clock *settableClock
	h     harness
}

func newLifetimeChanges(t *testing.T, grants storage.GrantStore) *lifetimeChanges {
	t.Helper()
	revocationEndpoint, err := fapi.ParseEndpointURL(testRevocationEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	clock := &settableClock{now: start}
	h := rebuilt(t, newHarness(t, server.ProfileFAPISecurity, true), func(c *server.Config) {
		c.Endpoints.Revocation = revocationEndpoint
	}, func(d *server.Dependencies) {
		d.Clock = clock
		d.Revocation = &expiringRevocationStore{clock: clock}
		d.Grants = grants
		d.GrantRegistry = memstore.NewGrantRegistry()
	})
	return &lifetimeChanges{t: t, start: start, clock: clock, h: h}
}

// at moves the clock to offset after the start and returns a server
// with refreshLifetime over the same stores.
func (c *lifetimeChanges) at(offset, refreshLifetime time.Duration) harness {
	c.t.Helper()
	c.clock.set(c.start.Add(offset))
	return rebuild(c.t, c.h, func(cfg *server.Config) { cfg.Limits.RefreshTokenLifetime = refreshLifetime }, c.h.deps)
}

// stored reports whether the GrantStore still redeems refreshToken.
func (c *lifetimeChanges) stored(refreshToken string) bool {
	_, err := c.h.deps.Grants.RedeemRefreshToken(context.Background(), storage.RefreshTokenRedemption{TokenHash: sha256.Sum256([]byte(refreshToken))})
	return err == nil
}

// checkRefused checks that refreshToken is refused at each offset with
// the server's 24h refresh token lifetime, and that ListGrants lists
// none of user-1's grants then.
func (c *lifetimeChanges) checkRefused(refreshToken string, offsets ...time.Duration) {
	c.t.Helper()
	for _, offset := range offsets {
		h := c.at(offset, 24*time.Hour)
		checkRefreshRefused(c.t, h, refreshToken, fmt.Sprintf("%v on, under 24h", offset))
		if n := len(listGrants(c.t, h, "user-1")); n != 0 {
			c.t.Errorf("ListGrants %v on lists %d grants, want none", offset, n)
		}
	}
}

// checkRefreshRefused checks that h refuses to refresh refreshToken, a
// revoked grant's, with invalid_grant.
func checkRefreshRefused(t *testing.T, h harness, refreshToken, when string) {
	t.Helper()
	_, err := refreshWith(t, h, refreshToken, "")
	switch {
	case err == nil:
		t.Errorf("refresh %s succeeded: the revoked grant's refresh token was redeemed", when)
	case serverErrorCode(t, err) != server.ErrorInvalidGrant:
		t.Errorf("refresh %s: %v, want invalid_grant", when, err)
	}
}

// checkStored checks whether the GrantStore still holds refreshToken
// after a revocation: never, once the store revoked the grant's refresh
// tokens itself, and still, for a record-only one.
func (c *lifetimeChanges) checkStored(kind grantStoreKind, refreshToken, after string) {
	c.t.Helper()
	if stored := c.stored(refreshToken); stored != kind.recordOnly {
		c.t.Fatalf("after %s, the GrantStore holds the refresh token: %v, want %v", after, stored, kind.recordOnly)
	}
}

// TestRevokedGrantStaysRevokedAfterRefreshLifetimeRaised: a refresh
// token issued under a 24h lifetime, the lifetime lowered to 1h, the
// grant revoked, then 24h restored. A revocation record sized from the
// 1h lifetime would have lapsed little more than an hour on, long before
// the token's own 24h are up; the token must stay refused until then,
// and its grant unlisted, whether the GrantStore revoked the token or
// only the grant's record refuses it.
func TestRevokedGrantStaysRevokedAfterRefreshLifetimeRaised(t *testing.T) {
	for _, kind := range grantStoreKinds {
		t.Run(kind.name, func(t *testing.T) {
			c := newLifetimeChanges(t, kind.of(memstore.NewGrantStore()))
			refreshToken := exchangeWithGrantID(t, c.at(0, 24*time.Hour), "grant-1")
			if err := c.at(time.Minute, time.Hour).server.RevokeGrant(context.Background(), "grant-1"); err != nil {
				t.Fatalf("RevokeGrant: %v", err)
			}
			c.checkStored(kind, refreshToken, "RevokeGrant")
			c.checkRefused(refreshToken, 3*time.Hour, 24*time.Hour-time.Second)
		})
	}
}

// TestRevokedGrantStaysRevokedOnAnInstanceWithALongerLifetime: two
// servers over the same stores at once, one with a 24h refresh token
// lifetime and one with 1h — an instance not yet redeployed, a canary,
// an administrative process with Limits of its own. The 1h one revokes
// the grant; the 24h one must go on refusing the grant's refresh token,
// past the time a record sized from 1h would have lapsed. It first
// presents the token at 1h7m, just after that time (1h6m5s, with the
// harness's other Limits), so with a record-only GrantStore the grant's
// record is what refuses it there, not the revocation of the token that
// a refusal leaves behind.
func TestRevokedGrantStaysRevokedOnAnInstanceWithALongerLifetime(t *testing.T) {
	for _, kind := range grantStoreKinds {
		t.Run(kind.name, func(t *testing.T) {
			c := newLifetimeChanges(t, kind.of(memstore.NewGrantStore()))
			long := c.at(0, 24*time.Hour)
			refreshToken := exchangeWithGrantID(t, long, "grant-1")
			if err := c.at(time.Minute, time.Hour).server.RevokeGrant(context.Background(), "grant-1"); err != nil {
				t.Fatalf("RevokeGrant on the 1h instance: %v", err)
			}
			c.checkStored(kind, refreshToken, "RevokeGrant on the 1h instance")
			for _, offset := range []time.Duration{time.Hour + 7*time.Minute, 2 * time.Hour, 24*time.Hour - time.Second} {
				c.clock.set(c.start.Add(offset))
				long.now = c.clock.Now()
				checkRefreshRefused(t, long, refreshToken, fmt.Sprintf("on the 24h instance %v on", offset))
			}
			if n := len(listGrants(t, long, "user-1")); n != 0 {
				t.Errorf("ListGrants on the 24h instance lists %d grants, want none", n)
			}
		})
	}
}

// TestRevokedGrantLeavesNoRedeemableRefreshToken: after RevokeGrant under
// a 1h lifetime, neither the client revoking its refresh token
// (RevokeToken) nor the application revoking the user's grants
// (RevokeSubjectGrants) leaves a refresh token that 24h, restored, makes
// redeemable again. RevokeToken finds the grant revoked and has nothing
// to revoke, yet the token is gone from the GrantStore afterwards either
// way, and its GrantRegistry entry with it: RevokeGrant removed both, or,
// with a record-only GrantStore, the revocation of the token that
// RevokeToken's refusal leaves behind did.
func TestRevokedGrantLeavesNoRedeemableRefreshToken(t *testing.T) {
	for _, kind := range grantStoreKinds {
		t.Run(kind.name+"/RevokeToken", func(t *testing.T) { testRevokeTokenAfterRevokeGrant(t, kind) })
		t.Run(kind.name+"/RevokeSubjectGrants", func(t *testing.T) { testRevokeSubjectGrantsAfterRevokeGrant(t, kind) })
	}
}

func testRevokeTokenAfterRevokeGrant(t *testing.T, kind grantStoreKind) {
	c := newLifetimeChanges(t, kind.of(memstore.NewGrantStore()))
	var deleted []string
	c.h.deps.GrantRegistry = deleteRecordingRegistry{memstore.NewGrantRegistry(), &deleted}
	issuing := c.at(0, 24*time.Hour)
	refreshToken := exchangeWithGrantID(t, issuing, "grant-1")
	listed := listGrants(t, issuing, "user-1")
	if len(listed) != 1 {
		t.Fatalf("ListGrants = %d grants, want 1", len(listed))
	}
	h := c.at(time.Minute, time.Hour)
	if err := h.server.RevokeGrant(context.Background(), "grant-1"); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}
	if _, err := h.server.RevokeToken(context.Background(), server.TokenRevocationRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_assertion", h.clientAssertion(t)),
			formParam("client_assertion_type", clientassertion.AssertionType),
			formParam("token", refreshToken),
		}},
	}); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	if c.stored(refreshToken) {
		t.Error("after RevokeGrant and RevokeToken, the GrantStore still holds the refresh token")
	}
	if !slices.Contains(deleted, listed[0].ID) {
		t.Errorf("after RevokeGrant and RevokeToken, DeleteGrant calls = %v, want the grant's entry %q", deleted, listed[0].ID)
	}
	c.checkRefused(refreshToken, 3*time.Hour, 24*time.Hour-time.Second)
}

func testRevokeSubjectGrantsAfterRevokeGrant(t *testing.T, kind grantStoreKind) {
	c := newLifetimeChanges(t, kind.of(memstore.NewGrantStore()))
	refreshToken := exchangeWithGrantID(t, c.at(0, 24*time.Hour), "grant-1")
	h := c.at(time.Minute, time.Hour)
	if err := h.server.RevokeGrant(context.Background(), "grant-1"); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}
	if n, err := h.server.RevokeSubjectGrants(context.Background(), mustSubjectID(t, "user-1")); n != 0 || err != nil {
		t.Fatalf("RevokeSubjectGrants after RevokeGrant = %d, %v; want 0, nil (the grant is no longer listed)", n, err)
	}
	c.checkStored(kind, refreshToken, "RevokeGrant and RevokeSubjectGrants")
	c.checkRefused(refreshToken, 3*time.Hour, 24*time.Hour-time.Second)
}

// TestReusedCodesGrantStaysRevokedAfterRefreshLifetimeRaised is the
// authorization code reuse variant: the code's refresh token, issued
// under 24h and not recorded against the code by the GrantStore, so the
// reuse, under 1h, revokes it only through the code's grant. Once 24h is
// restored the token must stay refused, past the time a code grant
// record sized from 1h would have lapsed.
func TestReusedCodesGrantStaysRevokedAfterRefreshLifetimeRaised(t *testing.T) {
	for _, kind := range grantStoreKinds {
		t.Run(kind.name, func(t *testing.T) {
			c := newLifetimeChanges(t, kind.of(unrecordedGrantStore{memstore.NewGrantStore()}))
			h := c.at(0, 24*time.Hour)
			code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts", "offline_access"})
			exchange := func(h harness) (server.TokenResult, error) {
				return h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
					HTTP:       server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
					DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
				})
			}
			tokens, err := exchange(h)
			if err != nil {
				t.Fatalf("ExchangeAuthorizationCode: %v", err)
			}
			refreshToken := tokens.RefreshToken.Reveal()
			if _, err := exchange(c.at(30*time.Second, time.Hour)); serverErrorCode(t, err) != server.ErrorInvalidGrant {
				t.Fatalf("reusing the code: %v, want invalid_grant", err)
			}
			c.checkStored(kind, refreshToken, "the code's reuse")
			c.checkRefused(refreshToken, 3*time.Hour, 24*time.Hour-time.Second)
		})
	}
}

// failingGrantRevoker is memstore's GrantStore whose
// RevokeGrantRefreshTokens fails while down is set: before revoking
// anything, or, with partWay, once it has revoked the tokens, which it
// reports with its error, as a store failing part way must.
type failingGrantRevoker struct {
	*memstore.GrantStore
	down, partWay bool
}

func (s *failingGrantRevoker) RevokeGrantRefreshTokens(ctx context.Context, grantKey string) ([][32]byte, error) {
	if !s.down {
		return s.GrantStore.RevokeGrantRefreshTokens(ctx, grantKey)
	}
	if !s.partWay {
		return nil, errStoreDown
	}
	revoked, err := s.GrantStore.RevokeGrantRefreshTokens(ctx, grantKey)
	return revoked, errors.Join(err, errStoreDown)
}

// recoveringRegistry is memstore's GrantRegistry whose DeleteGrant fails
// while down is set.
type recoveringRegistry struct {
	*memstore.GrantRegistry
	down bool
}

func (r *recoveringRegistry) DeleteGrant(ctx context.Context, key string) error {
	if r.down {
		return errors.New("registry down")
	}
	return r.GrantRegistry.DeleteGrant(ctx, key)
}

// TestRevokeGrantSaysWhenItsRefreshTokensRemain: RevokeGrant records the
// grant as revoked before revoking its refresh tokens, so the grant is
// refused whatever fails after, and its error tells the two failures
// apart. The GrantStore failing to revoke the tokens, before revoking
// any or part way, is an error saying they couldn't all be revoked, and
// calling RevokeGrant again revokes the rest. The GrantRegistry failing
// to remove their entries is an error saying the grant and its refresh
// tokens are revoked, which promises no retry: one, once the registry
// has recovered, succeeds, and the entry still isn't listed.
func TestRevokeGrantSaysWhenItsRefreshTokensRemain(t *testing.T) {
	t.Run("GrantStore", func(t *testing.T) { testRevokeGrantWithTheGrantStoreFailing(t, false) })
	t.Run("GrantStore part way", func(t *testing.T) { testRevokeGrantWithTheGrantStoreFailing(t, true) })
	t.Run("GrantRegistry", testRevokeGrantWithTheGrantRegistryFailing)
}

// testRevokeGrantWithTheGrantStoreFailing has the GrantStore fail to
// revoke the grant's refresh tokens, before revoking any or, partWay,
// after revoking them. The grant is recorded as revoked, a second call
// revokes what the first left, and the registry entry of every token the
// store reports revoked is removed, even by the call that failed.
func testRevokeGrantWithTheGrantStoreFailing(t *testing.T, partWay bool) {
	ctx := context.Background()
	grants := &failingGrantRevoker{GrantStore: memstore.NewGrantStore(), down: true, partWay: partWay}
	c := newLifetimeChanges(t, grants)
	var deleted []string
	c.h.deps.GrantRegistry = deleteRecordingRegistry{memstore.NewGrantRegistry(), &deleted}
	h := c.at(0, 24*time.Hour)
	refreshToken := exchangeWithGrantID(t, h, "grant-1")
	listed := listGrants(t, h, "user-1")
	if len(listed) != 1 {
		t.Fatalf("ListGrants = %d grants, want 1", len(listed))
	}
	err := h.server.RevokeGrant(ctx, "grant-1")
	if !errors.Is(err, errStoreDown) || !strings.Contains(err.Error(), "the grant is revoked, but its refresh tokens couldn't all be revoked (call RevokeGrant again to revoke the rest)") {
		t.Fatalf("RevokeGrant with the GrantStore failing = %v, want its error, saying the grant is revoked and to call it again", err)
	}
	if revoked, _ := h.deps.Revocation.(*expiringRevocationStore).IsRevoked(ctx, "grant:grant-1@"+testIssuer); !revoked {
		t.Fatal("the grant wasn't recorded as revoked")
	}
	if stored := c.stored(refreshToken); stored == partWay {
		t.Fatalf("test setup: after the failing GrantStore, the GrantStore holds the refresh token: %v, want %v", stored, !partWay)
	}
	if partWay && !slices.Contains(deleted, listed[0].ID) {
		t.Errorf("DeleteGrant calls = %v, want the entry %q of the token the failing GrantStore reported revoked", deleted, listed[0].ID)
	}
	grants.down = false
	if err := h.server.RevokeGrant(ctx, "grant-1"); err != nil {
		t.Fatalf("RevokeGrant again: %v", err)
	}
	if c.stored(refreshToken) {
		t.Error("calling RevokeGrant again left the refresh token stored")
	}
	if !slices.Contains(deleted, listed[0].ID) {
		t.Errorf("after RevokeGrant again, DeleteGrant calls = %v, want the grant's entry %q", deleted, listed[0].ID)
	}
}

// testRevokeGrantWithTheGrantRegistryFailing has the GrantRegistry fail
// to remove the revoked refresh token's entry. The error says the grant
// and its refresh tokens are revoked without promising that a retry
// removes the entry, which the store no longer reports; one, once the
// registry has recovered, succeeds, and ListGrants doesn't list the
// grant while its record lasts.
func testRevokeGrantWithTheGrantRegistryFailing(t *testing.T) {
	ctx := context.Background()
	registry := &recoveringRegistry{GrantRegistry: memstore.NewGrantRegistry(), down: true}
	c := newLifetimeChanges(t, memstore.NewGrantStore())
	c.h.deps.GrantRegistry = registry
	h := c.at(0, 24*time.Hour)
	refreshToken := exchangeWithGrantID(t, h, "grant-1")
	err := h.server.RevokeGrant(ctx, "grant-1")
	if err == nil || !strings.Contains(err.Error(), "the grant and its refresh tokens are revoked") || !strings.Contains(err.Error(), "registry down") {
		t.Fatalf("RevokeGrant with the GrantRegistry failing = %v, want its error, saying the grant and its refresh tokens are revoked", err)
	}
	if strings.Contains(err.Error(), "call RevokeGrant again") {
		t.Errorf("RevokeGrant with the GrantRegistry failing = %v, promising a retry that needn't remove the entry", err)
	}
	if c.stored(refreshToken) {
		t.Error("the refresh token is still stored")
	}
	registry.down = false
	if err := h.server.RevokeGrant(ctx, "grant-1"); err != nil {
		t.Fatalf("RevokeGrant again, the GrantRegistry recovered: %v", err)
	}
	if n := len(listGrants(t, h, "user-1")); n != 0 {
		t.Errorf("ListGrants after RevokeGrant again lists %d grants, want none", n)
	}
	c.checkRefused(refreshToken, 3*time.Hour, 24*time.Hour-time.Second)
}

// TestRevokeGrantRevokesOnlyItsGrantsRefreshTokens: the GrantStore
// revokes the revoked grant's refresh tokens only — not another grant's,
// nor those of a grant with the same ID that a server with another
// issuer, sharing the store, revokes — and the GrantRegistry loses the
// revoked grant's entry alone.
func TestRevokeGrantRevokesOnlyItsGrantsRefreshTokens(t *testing.T) {
	ctx := context.Background()
	c := newLifetimeChanges(t, memstore.NewGrantStore())
	var deleted []string
	c.h.deps.GrantRegistry = deleteRecordingRegistry{memstore.NewGrantRegistry(), &deleted}
	h := c.at(0, 24*time.Hour)
	revoked := exchangeWithGrantID(t, h, "grant-1")
	kept := exchangeWithGrantID(t, h, "grant-2")
	listedIDs := map[string]string{}
	for _, g := range listGrants(t, h, "user-1") {
		listedIDs[g.GrantID] = g.ID
	}
	tenantB, _ := otherTenant(t, h)
	if err := tenantB.RevokeGrant(ctx, "grant-2"); err != nil {
		t.Fatalf("tenant B RevokeGrant: %v", err)
	}
	if err := h.server.RevokeGrant(ctx, "grant-1"); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}
	if c.stored(revoked) {
		t.Error("the revoked grant's refresh token is still stored")
	}
	if want := listedIDs["grant-1"]; want == "" || !slices.Equal(deleted, []string{want}) {
		t.Errorf("DeleteGrant calls = %v, want the revoked grant's entry %q alone", deleted, want)
	}
	if !c.stored(kept) {
		t.Fatal("revoking grant-1, and grant-2 at another issuer, revoked this issuer's grant-2 refresh token")
	}
	if _, err := refreshWith(t, h, kept, ""); err != nil {
		t.Errorf("refreshing grant-2: %v", err)
	}
	if n := len(listGrants(t, h, "user-1")); n != 1 {
		t.Errorf("ListGrants lists %d grants, want grant-2's", n)
	}
}

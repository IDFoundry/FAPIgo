package sqlstore_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/sqlstore"
	"github.com/idfoundry/fapigo/storage"
)

// A grant registry revocation racing a refresh token's issuance: the
// issuance (a code exchange) records the grant in the registry, stores
// the refresh token, then confirms the grant is still recorded; the
// revocation (RevokeSubjectGrants, or RevokeListedGrant) lists the
// grant, revokes its refresh token, deletes the registry entry and
// revokes the token again. The revocation can read the token's hash
// from the registry before the token is stored, which is when the
// store's tombstone (RevokeRefreshToken) matters.

// raceRole is which side of a registry race a store call is made for.
type raceRole int

const (
	issuerRole raceRole = iota + 1
	revokerRole
)

type raceRoleKey struct{}

// raceContext is a context for role's calls, ended after a while so a
// schedule that can't be achieved fails rather than hangs.
func raceContext(t *testing.T, role raceRole) context.Context {
	ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), raceRoleKey{}, role), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func roleOf(ctx context.Context) raceRole {
	role, _ := ctx.Value(raceRoleKey{}).(raceRole)
	return role
}

// registryRace orders a registry race's store calls. Started is closed
// once the issuance has recorded its grant, when the revocation starts.
//
// When forced, the issuance's CreateRefreshToken waits for the
// revocation's first RevokeRefreshToken to return, and the revocation's
// DeleteGrant for the issuance to have confirmed its grant, or failed to
// store its token: the order in which a store that forgets a revocation
// of a token not yet stored left the token live and unlisted.
//
// When not, the issuance's CreateRefreshToken only waits for the
// revocation's first RevokeRefreshToken to start, so the two race; and
// the revocation's second RevokeRefreshToken waits until the issuance has
// returned and its token has been checked (checked), so what's checked is
// the store's own guarantee, not the server's second revocation.
type registryRace struct {
	forced                                        bool
	started, revoking, revoked, issued, checked   chan struct{}
	startOnce, revokingOnce, revokeOnce, iss, chk sync.Once
}

func newRegistryRace(forced bool) *registryRace {
	return &registryRace{
		forced: forced, started: make(chan struct{}), revoking: make(chan struct{}),
		revoked: make(chan struct{}), issued: make(chan struct{}), checked: make(chan struct{}),
	}
}

func (r *registryRace) signal(once *sync.Once, ch chan struct{}) { once.Do(func() { close(ch) }) }

// await waits for ch, or until ctx ends.
func await(ctx context.Context, ch chan struct{}) {
	select {
	case <-ch:
	case <-ctx.Done():
	}
}

// closed reports whether ch is closed.
func closed(ch chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// raceGrants is a GrantStore whose refresh token calls a registryRace
// orders.
type raceGrants struct {
	storage.GrantStore
	race *registryRace
}

func (g raceGrants) CreateRefreshToken(ctx context.Context, token storage.NewRefreshToken) error {
	if roleOf(ctx) != issuerRole {
		return g.GrantStore.CreateRefreshToken(ctx, token)
	}
	if g.race.forced {
		await(ctx, g.race.revoked)
	} else {
		await(ctx, g.race.revoking)
	}
	err := g.GrantStore.CreateRefreshToken(ctx, token)
	if err != nil {
		g.race.signal(&g.race.iss, g.race.issued)
	}
	return err
}

func (g raceGrants) RevokeRefreshToken(ctx context.Context, tokenHash [32]byte) error {
	if roleOf(ctx) != revokerRole {
		return g.GrantStore.RevokeRefreshToken(ctx, tokenHash)
	}
	if closed(g.race.revoked) && !g.race.forced {
		await(ctx, g.race.checked) // the second revocation
	}
	g.race.signal(&g.race.revokingOnce, g.race.revoking)
	err := g.GrantStore.RevokeRefreshToken(ctx, tokenHash)
	g.race.signal(&g.race.revokeOnce, g.race.revoked)
	return err
}

func (g raceGrants) Capabilities() storage.Capabilities {
	return g.GrantStore.(storage.StoreAssurance).Capabilities()
}

// raceRegistry is a GrantRegistry whose calls a registryRace orders.
type raceRegistry struct {
	storage.GrantRegistry
	race *registryRace
}

func (r raceRegistry) RecordGrant(ctx context.Context, entry storage.NewGrantEntry) error {
	err := r.GrantRegistry.RecordGrant(ctx, entry)
	if roleOf(ctx) == issuerRole {
		r.race.signal(&r.race.startOnce, r.race.started)
	}
	return err
}

func (r raceRegistry) ListGrants(ctx context.Context, listing storage.GrantListing) ([]storage.GrantEntry, error) {
	entries, err := r.GrantRegistry.ListGrants(ctx, listing)
	if roleOf(ctx) == issuerRole && listing.Key != "" {
		r.race.signal(&r.race.iss, r.race.issued) // the issuance's confirmation
	}
	return entries, err
}

func (r raceRegistry) DeleteGrant(ctx context.Context, key string) error {
	if roleOf(ctx) == revokerRole && r.race.forced {
		await(ctx, r.race.issued)
	}
	return r.GrantRegistry.DeleteGrant(ctx, key)
}

func (r raceRegistry) Capabilities() storage.Capabilities {
	return r.GrantRegistry.(storage.StoreAssurance).Capabilities()
}

// registryRaceServer is the AssuranceProduction deployment of
// flowDeployment over d with grants, a GrantRegistry and no revocation
// store (server.NoRevocation): grants carry no grant ID then, so only the
// registry's revocation of the refresh token ends one. race orders the
// store calls of the one built when it's set.
func registryRaceServer(t *testing.T, d *sqlstore.DB, grants storage.GrantStore, race *registryRace) *server.Server {
	t.Helper()
	cfg, deps := flowDeployment(t, d, grants, server.SystemClock{})
	deps.Revocation = server.NoRevocation{}
	if race != nil {
		deps.Grants, deps.GrantRegistry = raceGrants{grants, race}, raceRegistry{deps.GrantRegistry, race}
	}
	srv, err := server.New(cfg, deps)
	must(t, err)
	return srv
}

// AssuranceProduction accepts a server whose stores are all sqlstore's,
// with a GrantRegistry and Revocation declined (server.NoRevocation), on
// either database and with either Grants store: the configuration in
// which only the registry's revocation of a refresh token ends it, so the
// races below are ones a production deployment can meet.
func TestProductionAcceptsARegistryWithoutRevocation(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		d := freshDB(t, dialect)
		for _, grants := range []storage.GrantStore{d.Grants(), d.BatchingGrants()} {
			registryRaceServer(t, d, grants, nil)
		}
	})
}

// subjectRevocations are the two ways an application revokes a
// subject's listed grants.
var subjectRevocations = map[string]func(ctx context.Context, srv *server.Server, subject server.SubjectID) (int, error){
	"RevokeSubjectGrants": func(ctx context.Context, srv *server.Server, subject server.SubjectID) (int, error) {
		return srv.RevokeSubjectGrants(ctx, subject)
	},
	"RevokeListedGrant": func(ctx context.Context, srv *server.Server, subject server.SubjectID) (int, error) {
		listed, err := srv.ListGrants(ctx, subject)
		if err != nil || len(listed) == 0 {
			return 0, err
		}
		return 1, srv.RevokeListedGrant(ctx, subject, listed[0].ID)
	},
}

// raceOutcome is what a registry race's two sides returned: the
// exchange's refresh token and error, whether the store redeemed that
// token once both the exchange and the revocation's first revocation of
// it had returned, and how many grants the revocation revoked and its
// error.
type raceOutcome struct {
	refreshToken string
	exchangeErr  error
	liveAfter    bool
	checkErr     error
	revoked      int
	revokeErr    error
}

// raced runs one registry race on srv over race: the exchange of code,
// for the issuer, then a check of the token it issued against the store,
// grants; and, once the exchange has recorded its grant, revoke, for the
// revoker. The store only has to refuse the token once the revocation's
// first RevokeRefreshToken has returned, so the check waits for that
// call, which waits on nothing the issuer does after its exchange
// returns; in a race that isn't
// forced, the revocation's second RevokeRefreshToken waits for the check
// (see registryRace).
func raced(t *testing.T, srv *server.Server, grants storage.GrantStore, app flowClient, race *registryRace, code string, revoke func(context.Context, *server.Server, server.SubjectID) (int, error)) raceOutcome {
	t.Helper()
	subject := mustSubject(t)
	var out raceOutcome
	var wg sync.WaitGroup
	wg.Go(func() {
		defer race.signal(&race.chk, race.checked)
		ctx := raceContext(t, issuerRole)
		out.refreshToken, out.exchangeErr = app.exchange(ctx, srv, code)
		if out.exchangeErr == nil {
			await(ctx, race.revoked)
			_, err := grants.RedeemRefreshToken(context.Background(), storage.RefreshTokenRedemption{TokenHash: sha256.Sum256([]byte(out.refreshToken))})
			out.liveAfter = err == nil
			if err != nil && !isNotFound(err) {
				out.checkErr = err
			}
		}
	})
	wg.Go(func() {
		ctx := raceContext(t, revokerRole)
		await(ctx, race.started)
		out.revoked, out.revokeErr = revoke(ctx, srv, subject)
	})
	wg.Wait()
	must(t, out.checkErr)
	return out
}

// liveRefreshTokens is how many of the refresh tokens p's tables hold
// aren't tombstones.
func liveRefreshTokens(t *testing.T, p *place) int {
	t.Helper()
	_, db := p.open()
	var n int
	must(t, db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM "+p.prefix+"refresh_tokens WHERE revoked = 0").Scan(&n))
	return n
}

// A registry revocation that revokes a refresh token's hash before the
// token is stored refuses the token's issuance: the store's tombstone
// makes CreateRefreshToken fail, so the exchange issues no token, the
// revocation counts the grant, and nothing is left live or listed —
// whether or not the server's second revocation of the token, after the
// entry's deletion, would have caught a token stored anyway.
func TestRegistryRevocationBeforeTheTokenIsStoredRefusesTheIssuance(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		for name, revoke := range subjectRevocations {
			t.Run(name, func(t *testing.T) {
				p := newPlace(t, dialect)
				d := p.migrated()
				app := newFlowClient(t, d)
				race := newRegistryRace(true)
				srv := registryRaceServer(t, d, d.Grants(), race)
				out := raced(t, srv, d.Grants(), app, race, app.code(context.Background(), srv, time.Now(), ""), revoke)
				if out.exchangeErr == nil {
					t.Fatal("the code exchange issued a refresh token the revocation had already revoked")
				}
				if out.revoked != 1 || out.revokeErr != nil {
					t.Fatalf("revocation = %d, %v, want 1, nil", out.revoked, out.revokeErr)
				}
				checkNothingLeft(t, p, srv)
			})
		}
	})
}

// checkNothingLeft checks that p's tables hold no live refresh token and
// srv lists no grant: a second revocation revokes nothing.
func checkNothingLeft(t *testing.T, p *place, srv *server.Server) {
	t.Helper()
	if n := liveRefreshTokens(t, p); n != 0 {
		t.Fatalf("%d live refresh tokens left after the revocation", n)
	}
	if again, err := srv.RevokeSubjectGrants(context.Background(), mustSubject(t)); again != 0 || err != nil {
		t.Fatalf("a second RevokeSubjectGrants = %d, %v, want 0, nil", again, err)
	}
}

// raceIterations is how many races TestRegistryRevocationRacingIssuance
// runs on each database.
const raceIterations = 100

// Registry revocations racing issuances, the token's first revocation
// and its storing let go together, never leave a live refresh token: by
// the time both have returned, an issued token is already unredeemable
// in the store, before the server's second revocation of it, and after
// both revocations no token refreshes and no live row is left.
func TestRegistryRevocationRacingIssuance(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		p := newPlace(t, dialect)
		d := p.migrated()
		app := newFlowClient(t, d)
		var counts raceCounts
		for range raceIterations {
			counts.add(raceOnce(t, d, app))
		}
		t.Logf("%s: %d races: %d tokens issued, %d issuances refused", dialect, raceIterations, counts.issued, raceIterations-counts.issued)
		if counts.liveAfter != 0 || counts.liveAtTheEnd != 0 || liveRefreshTokens(t, p) != 0 {
			t.Fatalf("%d issued tokens redeemable once revoked, %d refreshing after both revocations, %d live rows left; want none",
				counts.liveAfter, counts.liveAtTheEnd, liveRefreshTokens(t, p))
		}
	})
}

// raceCounts counts TestRegistryRevocationRacingIssuance's races: those
// whose exchange issued a token, and those whose token the store
// redeemed once revoked, or refreshed after both revocations.
type raceCounts struct{ issued, liveAfter, liveAtTheEnd int }

func (c *raceCounts) add(issued, liveAfter, liveAtTheEnd bool) {
	c.issued += oneIf(issued)
	c.liveAfter += oneIf(liveAfter)
	c.liveAtTheEnd += oneIf(liveAtTheEnd)
}

// oneIf is 1 if yes, and 0 if not.
func oneIf(yes bool) int {
	if yes {
		return 1
	}
	return 0
}

// raceOnce runs one of TestRegistryRevocationRacingIssuance's races on
// d, reporting whether the exchange issued a token, whether the store
// redeemed it once revoked, and whether it refreshed after a second
// RevokeSubjectGrants.
func raceOnce(t *testing.T, d *sqlstore.DB, app flowClient) (issued, liveAfter, liveAtTheEnd bool) {
	t.Helper()
	race := newRegistryRace(false)
	srv := registryRaceServer(t, d, d.Grants(), race)
	out := raced(t, srv, d.Grants(), app, race, app.code(context.Background(), srv, time.Now(), ""), subjectRevocations["RevokeSubjectGrants"])
	must(t, out.revokeErr)
	if out.exchangeErr != nil {
		return false, false, false
	}
	_, err := srv.RevokeSubjectGrants(context.Background(), mustSubject(t))
	must(t, err)
	return true, out.liveAfter, app.refresh(srv, out.refreshToken) == nil
}

// mustSubject is the flow's end user's SubjectID.
func mustSubject(t *testing.T) server.SubjectID {
	t.Helper()
	subject, err := server.NewSubjectID(flowSubject)
	must(t, err)
	return subject
}

// isNotFound reports whether err is a store's unknown key.
func isNotFound(err error) bool { return errors.Is(err, sqlstore.ErrNotFound) }

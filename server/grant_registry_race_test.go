package server_test

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// deletingGrantStore is the harness's GrantStore revoking a refresh
// token as a SQL store does, by deleting it: revoking one it doesn't
// hold yet does nothing, so a token stored after its revocation is live.
// storage.GrantStore asks no more: only a token already created must
// stop redeeming once revoked.
type deletingGrantStore struct{ *fakeGrantStore }

func (g deletingGrantStore) RevokeRefreshToken(_ context.Context, tokenHash [32]byte) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.failRevokeRefresh != nil {
		return g.failRevokeRefresh
	}
	delete(g.refreshByHash, tokenHash)
	return nil
}

// storedRefreshTokens is how many refresh tokens g holds.
func (g deletingGrantStore) storedRefreshTokens() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.refreshByHash)
}

// raceStep is a point one side of a pinnedRace reaches, which the other
// side can wait for.
type raceStep struct {
	once    sync.Once
	reached chan struct{}
}

func newRaceStep() *raceStep { return &raceStep{reached: make(chan struct{})} }

// reach marks s reached.
func (s *raceStep) reach() { s.once.Do(func() { close(s.reached) }) }

// await blocks until s is reached, or until unless is: the side that
// would reach s has returned without it, and the order is broken.
func (s *raceStep) await(unless *raceStep) {
	select {
	case <-s.reached:
	case <-unless.reached:
	}
}

func (s *raceStep) wasReached() bool {
	select {
	case <-s.reached:
		return true
	default:
		return false
	}
}

// raceOrder is an order a refresh token's issuance and a revocation of
// its grant run in. In each, the revocation starts once the issuance has
// recorded the grant, so lists it, and revokes the refresh token before
// the token is stored, which a deletingGrantStore doesn't remember.
type raceOrder int

const (
	// confirmedBeforeDeleted: the issuance stores the token and confirms
	// the grant is still recorded before the revocation deletes its
	// entry, so the token is issued, and only a revocation after the
	// deletion can end it.
	confirmedBeforeDeleted raceOrder = iota

	// deletedBeforeStored: the revocation returns before the issuance
	// stores the token, so the issuance finds the entry gone when it
	// confirms, and must withdraw the token itself.
	deletedBeforeStored
)

// pinnedRace runs a refresh token's issuance and a revocation of its
// grant concurrently, held to order by pinnedGrants and pinnedRegistry.
type pinnedRace struct {
	order raceOrder

	// The issuance's steps: it recorded the grant, confirmed the grant
	// still recorded, and returned.
	recorded, confirmed, issued *raceStep

	// The revocation's: it revoked the refresh token (the first time),
	// and returned.
	revoked, revocationReturned *raceStep
}

func newPinnedRace(order raceOrder) *pinnedRace {
	return &pinnedRace{
		order:    order,
		recorded: newRaceStep(), confirmed: newRaceStep(), issued: newRaceStep(),
		revoked: newRaceStep(), revocationReturned: newRaceStep(),
	}
}

// run runs issue and, once the issuance has recorded the grant, revoke,
// concurrently, and returns the refresh token issue issued and both
// errors. Neither may use a testing.T: they run on goroutines of their
// own.
func (r *pinnedRace) run(issue func() (string, error), revoke func() error) (refreshToken string, issueErr, revokeErr error) {
	var wg sync.WaitGroup
	wg.Go(func() {
		defer r.issued.reach()
		refreshToken, issueErr = issue()
	})
	wg.Go(func() {
		defer r.revocationReturned.reach()
		r.recorded.await(r.issued)
		revokeErr = revoke()
	})
	wg.Wait()
	return refreshToken, issueErr, revokeErr
}

// kept reports whether r ran in its order: each step a side waited for
// was reached, rather than given up on.
func (r *pinnedRace) kept() bool {
	return r.recorded.wasReached() && r.revoked.wasReached() && r.confirmed.wasReached()
}

// pinnedGrants is a deletingGrantStore holding the issuance's
// CreateRefreshToken to race's order, and marking the revocation's
// revocation of the refresh token.
type pinnedGrants struct {
	deletingGrantStore
	race *pinnedRace
}

func (g pinnedGrants) CreateRefreshToken(ctx context.Context, token storage.NewRefreshToken) error {
	switch g.race.order {
	case confirmedBeforeDeleted:
		g.race.revoked.await(g.race.revocationReturned)
	case deletedBeforeStored:
		<-g.race.revocationReturned.reached
	}
	return g.deletingGrantStore.CreateRefreshToken(ctx, token)
}

func (g pinnedGrants) RevokeRefreshToken(ctx context.Context, tokenHash [32]byte) error {
	err := g.deletingGrantStore.RevokeRefreshToken(ctx, tokenHash)
	g.race.revoked.reach()
	return err
}

// pinnedRegistry is a memstore GrantRegistry marking the issuance's
// steps, and holding the revocation's DeleteGrant to race's order.
type pinnedRegistry struct {
	*memstore.GrantRegistry
	race *pinnedRace
}

func (r pinnedRegistry) RecordGrant(ctx context.Context, entry storage.NewGrantEntry) error {
	err := r.GrantRegistry.RecordGrant(ctx, entry)
	r.race.recorded.reach()
	return err
}

func (r pinnedRegistry) ListGrants(ctx context.Context, listing storage.GrantListing) ([]storage.GrantEntry, error) {
	entries, err := r.GrantRegistry.ListGrants(ctx, listing)
	if listing.Key != "" {
		// Only an issuance confirming its own entry lists by key.
		r.race.confirmed.reach()
	}
	return entries, err
}

func (r pinnedRegistry) DeleteGrant(ctx context.Context, key string) error {
	if r.race.order == confirmedBeforeDeleted {
		r.race.confirmed.await(r.race.issued)
	}
	return r.GrantRegistry.DeleteGrant(ctx, key)
}

// racedIssuance is a refresh token's issuance, ready to run: issue
// issues the token, calling the server alone, so it can run on a
// goroutine of its own, and refresh redeems the token it issued.
type racedIssuance struct {
	h       harness
	subject server.SubjectID
	issue   func() (string, error)
	refresh func(refreshToken string) error
}

// codeExchangeIssuance is an attested client's authorization code
// exchange with offline_access, on a server declining revocation: the
// grant has no code grant ID, so only deleting its refresh token ends
// it.
func codeExchangeIssuance(t *testing.T, grants storage.GrantStore, registry storage.GrantRegistry) racedIssuance {
	t.Helper()
	h, owner := registryHarness(t, registry, declineRevocation, func(deps *server.Dependencies) { deps.Grants = grants })
	req := owner.exchangeCodeRequest(owner.attestedCode(), testCodeVerifier)
	return racedIssuance{
		h: h, subject: mustSubjectID(t, "user-1"),
		issue: func() (string, error) {
			tokens, err := h.server.ExchangeAuthorizationCode(context.Background(), req)
			return tokens.RefreshToken.Reveal(), err
		},
		refresh: func(refreshToken string) error {
			_, err := owner.refresh(refreshToken)
			return err
		},
	}
}

// cibaIssuance is a CIBA token exchange with offline_access, on the
// backchannel harness, which declines revocation: the grant has no CIBA
// grant ID either.
func cibaIssuance(t *testing.T, grants storage.GrantStore, registry storage.GrantRegistry) racedIssuance {
	t.Helper()
	h := newHarnessWithBackchannelOptions(t, memstore.NewBackchannelAuthenticationStore(), nil, func(deps *server.Dependencies) {
		deps.Grants, deps.GrantRegistry = grants, registry
	})
	params := standardBackchannelParams(t)
	params["scope"] = json.RawMessage(`"openid accounts offline_access"`)
	required := beginBackchannel(t, h, params)
	if err := h.server.CompleteBackchannelAuthentication(context.Background(), server.CompleteBackchannelAuthenticationRequest{
		Handle: required.Handle,
		Result: authorizedAsGranting(t, h, "user-1", server.GrantedAuthorization{Scope: []string{"openid", "accounts", "offline_access"}}),
	}); err != nil {
		t.Fatalf("CompleteBackchannelAuthentication: %v", err)
	}
	req := server.BackchannelTokenExchangeRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_assertion", h.clientAssertion(t)),
			formParam("client_assertion_type", clientassertion.AssertionType),
			formParam("grant_type", server.CIBAGrantType),
			formParam("auth_req_id", required.AuthReqID.String()),
		}},
		DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
	}
	return racedIssuance{
		h: h, subject: mustSubjectID(t, "user-1"),
		issue: func() (string, error) {
			tokens, err := h.server.ExchangeBackchannelAuthentication(context.Background(), req)
			return tokens.RefreshToken.Reveal(), err
		},
		refresh: func(refreshToken string) error {
			_, err := h.server.RefreshAccessToken(context.Background(), server.RefreshTokenRequest{
				HTTP:       server.FormRequest{Parameters: refreshFormParams(h.clientAssertion(t), refreshToken, "")},
				DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
			})
			return err
		},
	}
}

// embedderIssuance is IssueRefreshToken without a GrantID: though the
// harness's revocation store is readable, only deleting its refresh
// token ends the grant.
func embedderIssuance(t *testing.T, grants storage.GrantStore, registry storage.GrantRegistry) racedIssuance {
	t.Helper()
	h, owner := registryHarness(t, registry, func(deps *server.Dependencies) { deps.Grants = grants })
	attested, binding := embedderTokenRequest(t, owner)
	subject := mustSubjectID(t, "holder-1")
	req := server.IssueRefreshTokenRequest{
		GrantType: preAuthorizedCodeGrant, Client: attested, Binding: binding,
		Subject: subject, Scope: []string{"accounts"},
	}
	return racedIssuance{
		h: h, subject: subject,
		issue: func() (string, error) {
			refreshToken, err := h.server.IssueRefreshToken(context.Background(), req)
			return refreshToken.Reveal(), err
		},
		refresh: func(refreshToken string) error {
			_, err := owner.refresh(refreshToken)
			return err
		},
	}
}

// TestRevocationRacingIssuanceEndsItsRefreshToken: RevokeSubjectGrants
// or RevokeListedGrant, run while the grant it lists is still being
// issued its refresh token, ends that token, on a GrantStore that keeps
// nothing of revoking a token it doesn't hold yet, for each grant only
// deleting its refresh token ends. The revocation lists the grant and
// revokes the token before it's stored; then either the issuance
// confirms the grant before the revocation deletes its entry, and the
// revocation's second revocation of the token, after the deletion,
// ends it, or the entry is gone when the issuance confirms, and the
// issuance withdraws the token itself.
func TestRevocationRacingIssuanceEndsItsRefreshToken(t *testing.T) {
	issuances := map[string]func(*testing.T, storage.GrantStore, storage.GrantRegistry) racedIssuance{
		"authorization code": codeExchangeIssuance,
		"CIBA":               cibaIssuance,
		"IssueRefreshToken":  embedderIssuance,
	}
	revocations := map[string]func(harness, server.SubjectID) error{
		"RevokeSubjectGrants": func(h harness, subject server.SubjectID) error {
			n, err := h.server.RevokeSubjectGrants(context.Background(), subject)
			if err == nil && n != 1 {
				return fmt.Errorf("revoked %d grants, want 1", n)
			}
			return err
		},
		"RevokeListedGrant": func(h harness, subject server.SubjectID) error {
			grants, err := h.server.ListGrants(context.Background(), subject)
			if err != nil {
				return err
			}
			if len(grants) != 1 {
				return fmt.Errorf("ListGrants = %d grants, want 1", len(grants))
			}
			return h.server.RevokeListedGrant(context.Background(), subject, grants[0].ID)
		},
	}
	orders := map[string]raceOrder{"confirmed before deleted": confirmedBeforeDeleted, "deleted before stored": deletedBeforeStored}
	for issuanceName, newIssuance := range issuances {
		for revocationName, revoke := range revocations {
			for orderName, order := range orders {
				t.Run(issuanceName+"/"+revocationName+"/"+orderName, func(t *testing.T) {
					testRevocationRace(t, newIssuance, revoke, order)
				})
			}
		}
	}
}

// testRevocationRace runs newIssuance's issuance and revoke in order,
// over a deletingGrantStore, and checks the revocation leaves no refresh
// token that still refreshes.
func testRevocationRace(t *testing.T, newIssuance func(*testing.T, storage.GrantStore, storage.GrantRegistry) racedIssuance, revoke func(harness, server.SubjectID) error, order raceOrder) {
	race := newPinnedRace(order)
	grants := deletingGrantStore{&fakeGrantStore{}}
	issuance := newIssuance(t, pinnedGrants{grants, race}, pinnedRegistry{memstore.NewGrantRegistry(), race})
	refreshToken, issueErr, revokeErr := race.run(issuance.issue, func() error { return revoke(issuance.h, issuance.subject) })
	switch {
	case !race.kept():
		t.Fatalf("the issuance (%v) and the revocation (%v) didn't run in order", issueErr, revokeErr)
	case revokeErr != nil:
		t.Fatalf("revocation: %v, want the grant revoked", revokeErr)
	case order == confirmedBeforeDeleted && issueErr != nil:
		t.Fatalf("issuance: %v, want the refresh token issued: its grant was still recorded when it confirmed", issueErr)
	case order == deletedBeforeStored && issueErr == nil:
		t.Fatal("issuance succeeded, want it refused: its grant's entry was gone when it confirmed")
	}
	if issueErr == nil {
		err := issuance.refresh(refreshToken)
		if err == nil {
			t.Fatal("the refresh token issued as its grant was revoked still refreshes")
		}
		requireInvalidGrant(t, err)
	}
	if n := grants.storedRefreshTokens(); n != 0 {
		t.Errorf("%d refresh tokens stored after the revocation, want none", n)
	}
	if left := listGrants(t, issuance.h, issuance.subject.String()); len(left) != 0 {
		t.Errorf("ListGrants after the revocation = %+v, want none", left)
	}
}

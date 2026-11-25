package server_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// registryHarness is newRevocationHarness rebuilt with registry as
// Dependencies.GrantRegistry, and an attested instance of its client.
// Each mutate then changes the Dependencies further: one replacing
// Grants leaves h.grants unused.
func registryHarness(t *testing.T, registry storage.GrantRegistry, mutate ...func(*server.Dependencies)) (harness, *attestedInstance) {
	t.Helper()
	attesterKey := generateKey(t)
	h := newRevocationHarness(t, attesterKey)
	deps := h.deps
	deps.GrantRegistry = registry
	for _, m := range mutate {
		m(&deps)
	}
	srv, err := server.New(h.cfg, deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	h.server, h.deps = srv, deps
	return h, &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}
}

func listGrants(t *testing.T, h harness, subject string) []server.ListedGrant {
	t.Helper()
	grants, err := h.server.ListGrants(context.Background(), mustSubjectID(t, subject))
	if err != nil {
		t.Fatalf("ListGrants(%s): %v", subject, err)
	}
	return grants
}

// TestListGrantsListsRefreshTokenGrants: a grant is listed for the user
// who authorized it once its refresh token is issued, with what was
// granted, and for nobody else.
func TestListGrantsListsRefreshTokenGrants(t *testing.T) {
	h, owner := registryHarness(t, memstore.NewGrantRegistry())
	owner.issueRefreshToken()

	grants := listGrants(t, h, "user-1")
	if len(grants) != 1 {
		t.Fatalf("ListGrants(user-1) = %d grants, want 1", len(grants))
	}
	g := grants[0]
	if g.ID == "" || g.ClientID != testClientID || g.GrantType != "authorization_code" || strings.Join(g.Scope, " ") != "openid accounts offline_access" {
		t.Errorf("listed grant = %+v", g)
	}
	if !g.ExpiresAt.Equal(g.IssuedAt.Add(h.cfg.Limits.RefreshTokenLifetime)) {
		t.Errorf("ExpiresAt = %v, want IssuedAt %v plus the refresh token lifetime", g.ExpiresAt, g.IssuedAt)
	}
	if others := listGrants(t, h, "user-2"); len(others) != 0 {
		t.Errorf("ListGrants(user-2) = %+v, want none", others)
	}
}

// TestRevokeListedGrant: revoking a listed grant ends its refresh token
// and unlists it; its ID revokes nothing for another subject, or twice.
func TestRevokeListedGrant(t *testing.T) {
	h, owner := registryHarness(t, memstore.NewGrantRegistry())
	refreshToken := owner.issueRefreshToken()
	if _, err := owner.refresh(refreshToken); err != nil {
		t.Fatalf("refresh before revocation: %v", err)
	}
	id := listGrants(t, h, "user-1")[0].ID
	ctx := context.Background()

	if err := h.server.RevokeListedGrant(ctx, mustSubjectID(t, "user-2"), id); !errors.Is(err, server.ErrGrantNotListed) {
		t.Fatalf("RevokeListedGrant(another subject) = %v, want ErrGrantNotListed", err)
	}
	if err := h.server.RevokeListedGrant(ctx, mustSubjectID(t, "user-1"), id); err != nil {
		t.Fatalf("RevokeListedGrant: %v", err)
	}
	if _, err := owner.refresh(refreshToken); err == nil {
		t.Error("refresh after RevokeListedGrant succeeded, want invalid_grant")
	}
	if grants := listGrants(t, h, "user-1"); len(grants) != 0 {
		t.Errorf("ListGrants after revocation = %+v, want none", grants)
	}
	if err := h.server.RevokeListedGrant(ctx, mustSubjectID(t, "user-1"), id); !errors.Is(err, server.ErrGrantNotListed) {
		t.Errorf("RevokeListedGrant again = %v, want ErrGrantNotListed", err)
	}
}

// TestRevokeListedGrantNamedByTheApplication: a grant the application
// named (IssueRefreshTokenRequest.GrantID) is revoked by that name too,
// so its access tokens stop working at a resource server.
func TestRevokeListedGrantNamedByTheApplication(t *testing.T) {
	h, owner := registryHarness(t, memstore.NewGrantRegistry())
	attested, binding := embedderTokenRequest(t, owner)
	if _, err := h.server.IssueRefreshToken(context.Background(), server.IssueRefreshTokenRequest{
		GrantType: preAuthorizedCodeGrant, Client: attested, Binding: binding,
		Subject: mustSubjectID(t, "holder-1"), Scope: []string{"accounts"}, GrantID: "grant-1",
	}); err != nil {
		t.Fatalf("IssueRefreshToken: %v", err)
	}
	grants := listGrants(t, h, "holder-1")
	if len(grants) != 1 || grants[0].GrantID != "grant-1" || grants[0].GrantType != preAuthorizedCodeGrant {
		t.Fatalf("ListGrants(holder-1) = %+v, want grant-1", grants)
	}
	if err := h.server.RevokeListedGrant(context.Background(), mustSubjectID(t, "holder-1"), grants[0].ID); err != nil {
		t.Fatalf("RevokeListedGrant: %v", err)
	}
	h.revocation.mu.Lock()
	_, revoked := h.revocation.until["grant:grant-1@"+testIssuer]
	h.revocation.mu.Unlock()
	if !revoked {
		t.Error("RevokeListedGrant didn't revoke the grant's GrantID")
	}
}

// TestListGrantsLeavesOutGrantsRevokedOtherwise: a grant revoked through
// RevokeToken or RevokeGrant isn't listed.
func TestListGrantsLeavesOutGrantsRevokedOtherwise(t *testing.T) {
	t.Run("RevokeToken", func(t *testing.T) {
		h, owner := registryHarness(t, memstore.NewGrantRegistry())
		refreshToken := owner.issueRefreshToken()
		if err := owner.revoke(formParam("token", refreshToken)); err != nil {
			t.Fatalf("RevokeToken: %v", err)
		}
		if grants := listGrants(t, h, "user-1"); len(grants) != 0 {
			t.Errorf("ListGrants after RevokeToken = %+v, want none", grants)
		}
	})
	t.Run("RevokeGrant", func(t *testing.T) {
		h, owner := registryHarness(t, memstore.NewGrantRegistry())
		attested, binding := embedderTokenRequest(t, owner)
		if _, err := h.server.IssueRefreshToken(context.Background(), server.IssueRefreshTokenRequest{
			GrantType: preAuthorizedCodeGrant, Client: attested, Binding: binding,
			Subject: mustSubjectID(t, "holder-1"), Scope: []string{"accounts"}, GrantID: "grant-1",
		}); err != nil {
			t.Fatalf("IssueRefreshToken: %v", err)
		}
		if err := h.server.RevokeGrant(context.Background(), "grant-1"); err != nil {
			t.Fatalf("RevokeGrant: %v", err)
		}
		if grants := listGrants(t, h, "holder-1"); len(grants) != 0 {
			t.Errorf("ListGrants after RevokeGrant = %+v, want none", grants)
		}
	})
}

// failingRegistry fails every RecordGrant.
type failingRegistry struct{ *memstore.GrantRegistry }

func (failingRegistry) RecordGrant(context.Context, storage.NewGrantEntry) error {
	return errors.New("registry down")
}

// TestGrantNotRecordedNoRefreshToken: a grant the registry couldn't
// record gets no refresh token, so none exists that ListGrants can't
// show.
func TestGrantNotRecordedNoRefreshToken(t *testing.T) {
	h, owner := registryHarness(t, failingRegistry{memstore.NewGrantRegistry()})
	attested, binding := embedderTokenRequest(t, owner)
	if _, err := h.server.IssueRefreshToken(context.Background(), server.IssueRefreshTokenRequest{
		GrantType: preAuthorizedCodeGrant, Client: attested, Binding: binding,
		Subject: mustSubjectID(t, "holder-1"), Scope: []string{"accounts"},
	}); err == nil {
		t.Fatal("IssueRefreshToken with the registry down = nil error, want error")
	}
}

func TestListGrantsNeedsTheRegistry(t *testing.T) {
	h := newRevocationHarness(t, generateKey(t))
	if _, err := h.server.ListGrants(context.Background(), mustSubjectID(t, "user-1")); err == nil || !strings.Contains(err.Error(), "Dependencies.GrantRegistry") {
		t.Errorf("ListGrants without a registry = %v, want it to name the dependency", err)
	}
	if err := h.server.RevokeListedGrant(context.Background(), mustSubjectID(t, "user-1"), "id"); err == nil || errors.Is(err, server.ErrGrantNotListed) {
		t.Errorf("RevokeListedGrant without a registry = %v, want a configuration error", err)
	}
}

// declaredRegistry is a GrantRegistry declaring caps.
type declaredRegistry struct {
	*memstore.GrantRegistry
	caps storage.Capabilities
}

func (r declaredRegistry) Capabilities() storage.Capabilities { return r.caps }

func TestProductionChecksGrantRegistry(t *testing.T) {
	for name, tc := range map[string]struct {
		registry storage.GrantRegistry
		want     string
	}{
		"memstore":    {memstore.NewGrantRegistry(), "grant_registry must implement storage.StoreAssurance"},
		"not durable": {declaredRegistry{memstore.NewGrantRegistry(), storage.Capabilities{}}, "grant_registry must declare Durable"},
		"durable":     {declaredRegistry{memstore.NewGrantRegistry(), storage.Capabilities{Durable: true}}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			err := productionNew(t, func(deps *server.Dependencies) { deps.GrantRegistry = tc.registry })
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("New(production, %s registry) = %v, want nil", name, err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("New(production, %s registry) = %v, want %q", name, err, tc.want)
			}
		})
	}
}

// stubRegistry lists entries for any subject, and fails DeleteGrant with
// deleteErr; listErr fails ListGrants.
type stubRegistry struct {
	entries   []storage.GrantEntry
	listErr   error
	deleteErr error
	deleted   []string
}

func (r *stubRegistry) RecordGrant(context.Context, storage.NewGrantEntry) error { return nil }
func (r *stubRegistry) ListGrants(context.Context, storage.GrantListing) ([]storage.GrantEntry, error) {
	return r.entries, r.listErr
}
func (r *stubRegistry) DeleteGrant(_ context.Context, key string) error {
	r.deleted = append(r.deleted, key)
	return r.deleteErr
}

// registryEntry is a GrantEntry holding record fields as the server
// writes them, for subject, issued at issuedAt.
func registryEntry(t *testing.T, h harness, name, issuer, subject string, issuedAt time.Time, extra map[string]any) storage.GrantEntry {
	t.Helper()
	hash := sha256.Sum256([]byte(name))
	record := map[string]any{"v": 1, "iss": issuer, "rth": hash[:], "sub": subject, "issued_at": issuedAt}
	for k, v := range extra {
		record[k] = v
	}
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	return storage.GrantEntry{Key: registryKey(name), ClientID: testClientID, Record: raw, ExpiresAt: h.now.Add(time.Hour)}
}

// registryKey is the entry key registryEntry gives name: derived from
// its refresh token hash, as the server derives one.
func registryKey(name string) string {
	return server.GrantEntryKey(sha256.Sum256([]byte(name)))
}

func stubRegistryHarness(t *testing.T, registry *stubRegistry) harness {
	t.Helper()
	h, _ := registryHarness(t, registry)
	return h
}

// TestListGrantsReadsEntries: entries are listed oldest first, with
// their authorization details, and one written by another issuer, for
// another subject or past its expiry is left out. (The older one is
// issued a minute before, within the harness's 5-minute refresh token
// lifetime: ListGrants leaves out an entry issued longer ago, see
// TestListGrantsJudgesExpiryByTheCurrentRefreshLifetime.)
func TestListGrantsReadsEntries(t *testing.T) {
	registry := &stubRegistry{}
	h := stubRegistryHarness(t, registry)
	expired := registryEntry(t, h, "expired", testIssuer, "user-1", h.now, nil)
	expired.ExpiresAt = h.now
	registry.entries = []storage.GrantEntry{
		registryEntry(t, h, "newer", testIssuer, "user-1", h.now, nil),
		registryEntry(t, h, "older", testIssuer, "user-1", h.now.Add(-time.Minute), map[string]any{
			"authorization_details": []map[string]any{{"type": "payment", "amount": "SGD 5"}},
		}),
		registryEntry(t, h, "foreign", "https://other-as.example", "user-1", h.now, nil),
		registryEntry(t, h, "another subject", testIssuer, "user-2", h.now, nil),
		expired,
	}
	grants := listGrants(t, h, "user-1")
	if len(grants) != 2 || grants[0].ID != registryKey("older") || grants[1].ID != registryKey("newer") {
		t.Fatalf("ListGrants = %+v, want older then newer", grants)
	}
	if len(grants[0].AuthorizationDetails) != 1 || !strings.Contains(string(grants[0].AuthorizationDetails[0]), `"payment"`) {
		t.Errorf("AuthorizationDetails = %s, want the payment", grants[0].AuthorizationDetails)
	}
}

// TestListGrantsRefusesUnreadableEntries: an entry the server can't
// decode, or whose store can't answer, fails the listing rather than
// hiding a grant.
func TestListGrantsRefusesUnreadableEntries(t *testing.T) {
	for name, registry := range map[string]*stubRegistry{
		"undecodable":        {entries: []storage.GrantEntry{{Key: "k", Record: json.RawMessage(`{`)}}},
		"bad details":        {},
		"store can't answer": {listErr: errors.New("registry down")},
	} {
		t.Run(name, func(t *testing.T) {
			h := stubRegistryHarness(t, registry)
			if name == "bad details" {
				registry.entries = []storage.GrantEntry{registryEntry(t, h, "k", testIssuer, "user-1", h.now, map[string]any{"authorization_details": "not a list"})}
			}
			if _, err := h.server.ListGrants(context.Background(), mustSubjectID(t, "user-1")); err == nil {
				t.Fatal("ListGrants = nil error, want error")
			}
			if err := h.server.RevokeListedGrant(context.Background(), mustSubjectID(t, "user-1"), registryKey("k")); err == nil || errors.Is(err, server.ErrGrantNotListed) {
				t.Fatal("revoking = nil error, want error")
			}
		})
	}
}

func TestListGrantsRefusesAnEmptySubject(t *testing.T) {
	h := stubRegistryHarness(t, &stubRegistry{})
	if _, err := h.server.ListGrants(context.Background(), server.SubjectID{}); err == nil {
		t.Fatal("ListGrants(zero SubjectID) = nil error, want error")
	}
}

// TestRevokeListedGrantKeepsAnEntryItCouldntFinish: a grant whose
// registry entry couldn't be deleted is reported, for a retry.
func TestRevokeListedGrantKeepsAnEntryItCouldntFinish(t *testing.T) {
	registry := &stubRegistry{deleteErr: errors.New("registry down")}
	h := stubRegistryHarness(t, registry)
	registry.entries = []storage.GrantEntry{registryEntry(t, h, "k", testIssuer, "user-1", h.now, nil)}
	if err := h.server.RevokeListedGrant(context.Background(), mustSubjectID(t, "user-1"), registryKey("k")); err == nil {
		t.Fatal("RevokeListedGrant with the registry down = nil error, want error")
	}
	if len(registry.deleted) != 1 {
		t.Errorf("DeleteGrant called %d times, want once", len(registry.deleted))
	}
}

// TestRevokeListedGrantRefusesAnEntryWithoutItsToken: an entry whose
// refresh token hash isn't the one its key is derived from (missing,
// short, or another token's, as a forged unsealed record's could be)
// isn't listed, so can't be revoked as the grant it claims to be.
func TestRevokeListedGrantRefusesAnEntryWithoutItsToken(t *testing.T) {
	for name, rth := range map[string]any{"short": []byte{1, 2}, "another token's": sha256.Sum256([]byte("other"))} {
		t.Run(name, func(t *testing.T) {
			registry := &stubRegistry{}
			h := stubRegistryHarness(t, registry)
			if hash, ok := rth.([32]byte); ok {
				rth = hash[:]
			}
			registry.entries = []storage.GrantEntry{registryEntry(t, h, "k", testIssuer, "user-1", h.now, map[string]any{"rth": rth})}
			if grants := listGrants(t, h, "user-1"); len(grants) != 0 {
				t.Errorf("ListGrants = %+v, want the mismatched entry left out", grants)
			}
			if err := h.server.RevokeListedGrant(context.Background(), mustSubjectID(t, "user-1"), registryKey("k")); !errors.Is(err, server.ErrGrantNotListed) {
				t.Fatalf("RevokeListedGrant(mismatched entry) = %v, want ErrGrantNotListed", err)
			}
			if len(registry.deleted) != 0 {
				t.Error("the mismatched entry was deleted")
			}
		})
	}
}

// TestRevokeListedGrantReportsEachFailure: a revocation that fails part
// way is reported, and the entry isn't deleted, so a retry finishes.
func TestRevokeListedGrantReportsEachFailure(t *testing.T) {
	for name, tc := range map[string]struct {
		extra map[string]any
		fail  func(h harness)
	}{
		"grant ID":      {map[string]any{"grant_id": "grant-1"}, func(h harness) { h.revocation.fail = errors.New("revocation down") }},
		"code grant":    {map[string]any{"code_grant_id": "code-1"}, func(h harness) { h.revocation.fail = errors.New("revocation down") }},
		"refresh token": {nil, func(h harness) { h.grants.failRevokeRefresh = errors.New("grants down") }},
	} {
		t.Run(name, func(t *testing.T) {
			registry := &stubRegistry{}
			h := stubRegistryHarness(t, registry)
			registry.entries = []storage.GrantEntry{registryEntry(t, h, "k", testIssuer, "user-1", h.now, tc.extra)}
			tc.fail(h)
			if err := h.server.RevokeListedGrant(context.Background(), mustSubjectID(t, "user-1"), registryKey("k")); err == nil {
				t.Fatal("RevokeListedGrant = nil error, want the failure")
			}
			if len(registry.deleted) != 0 {
				t.Error("the entry was deleted though revoking it failed")
			}
		})
	}
}

// outageAfterDelete is a memstore GrantRegistry whose first DeleteGrant
// takes grants down once it has deleted the entry: an outage starting
// between a revocation's deletion of a grant's entry and its second
// revocation of the grant's refresh token. With registryToo, RecordGrant
// fails from then on as well.
type outageAfterDelete struct {
	*memstore.GrantRegistry
	grants      *fakeGrantStore
	registryToo bool
	down        bool
}

func (r *outageAfterDelete) RecordGrant(ctx context.Context, entry storage.NewGrantEntry) error {
	if r.down && r.registryToo {
		return errors.New("registry down")
	}
	return r.GrantRegistry.RecordGrant(ctx, entry)
}

func (r *outageAfterDelete) DeleteGrant(ctx context.Context, key string) error {
	err := r.GrantRegistry.DeleteGrant(ctx, key)
	if !r.down {
		r.down = true
		r.grants.failRevokeRefresh = errors.New("grants down")
	}
	return err
}

// declineRevocation makes a registryHarness server decline revocation,
// so a code grant has no code grant ID: only deleting its refresh token
// ends it.
func declineRevocation(deps *server.Dependencies) { deps.Revocation = server.NoRevocation{} }

// TestRevokeListedGrantReportsAFailedSecondRevocation: revoking a
// grant's refresh token again once its entry is deleted, and failing, is
// reported as a failure before the deletion is, with the entry recorded
// again: the grant is still listed, so a retry finishes the job. An
// entry the registry can't record again is reported as well.
func TestRevokeListedGrantReportsAFailedSecondRevocation(t *testing.T) {
	ctx := context.Background()
	subject := mustSubjectID(t, "user-1")
	for name, revoke := range map[string]func(h harness, id string) (revoked int, err error){
		"RevokeListedGrant": func(h harness, id string) (int, error) {
			return 0, h.server.RevokeListedGrant(ctx, subject, id)
		},
		"RevokeSubjectGrants": func(h harness, _ string) (int, error) {
			return h.server.RevokeSubjectGrants(ctx, subject)
		},
	} {
		t.Run(name, func(t *testing.T) {
			checkFailedSecondRevocationRetried(t, name, subject, revoke)
		})
	}
	t.Run("registry down too", func(t *testing.T) {
		registry := &outageAfterDelete{GrantRegistry: memstore.NewGrantRegistry(), registryToo: true}
		h, owner := registryHarness(t, registry, declineRevocation)
		registry.grants = h.grants
		owner.issueRefreshToken()
		err := h.server.RevokeListedGrant(ctx, subject, listGrants(t, h, "user-1")[0].ID)
		if err == nil || !strings.Contains(err.Error(), "grants down") || !strings.Contains(err.Error(), "registry down") {
			t.Fatalf("RevokeListedGrant = %v, want both failures reported", err)
		}
	})
}

// checkFailedSecondRevocationRetried issues user-1 a refresh token over
// an outageAfterDelete registry, on a server declining revocation, then
// checks that revoke, named name, reports the failed second revocation
// of the token, counting nothing revoked, and leaves the grant listed,
// and that RevokeSubjectGrants(subject), retried once grants are back,
// ends it.
func checkFailedSecondRevocationRetried(t *testing.T, name string, subject server.SubjectID, revoke func(h harness, id string) (revoked int, err error)) {
	t.Helper()
	registry := &outageAfterDelete{GrantRegistry: memstore.NewGrantRegistry()}
	h, owner := registryHarness(t, registry, declineRevocation)
	registry.grants = h.grants
	refreshToken := owner.issueRefreshToken()
	id := listGrants(t, h, "user-1")[0].ID
	if n, err := revoke(h, id); n != 0 || err == nil || !strings.Contains(err.Error(), "grants down") {
		t.Fatalf("%s = %d, %v, want the failed revocation reported, and nothing counted revoked", name, n, err)
	}
	if listed := listGrants(t, h, "user-1"); len(listed) != 1 || listed[0].ID != id {
		t.Fatalf("ListGrants after = %+v, want the grant still listed, for a retry", listed)
	}
	h.grants.failRevokeRefresh = nil
	if n, err := h.server.RevokeSubjectGrants(context.Background(), subject); n != 1 || err != nil {
		t.Fatalf("RevokeSubjectGrants retried = %d, %v, want the grant revoked", n, err)
	}
	if _, err := owner.refresh(refreshToken); err == nil {
		t.Error("the revoked grant's refresh token still refreshes")
	}
}

// TestRevokeTokenReportsARegistryFailure: a refresh token revoked at the
// revocation endpoint whose registry entry couldn't be removed is a
// server error, so the client retries.
func TestRevokeTokenReportsARegistryFailure(t *testing.T) {
	_, owner := registryHarness(t, undeletableRegistry{memstore.NewGrantRegistry()})
	refreshToken := owner.issueRefreshToken()
	err := owner.revoke(formParam("token", refreshToken))
	var serverErr *server.Error
	if !errors.As(err, &serverErr) || serverErr.Code() != server.ErrorServerError {
		t.Fatalf("RevokeToken with the registry down = %v, want server_error", err)
	}
}

// TestRevokeSubjectGrants revokes every grant of one subject, and none
// of another's.
func TestRevokeSubjectGrants(t *testing.T) {
	h, owner := registryHarness(t, memstore.NewGrantRegistry())
	first := owner.issueRefreshToken()
	second := owner.issueRefreshToken()
	attested, binding := embedderTokenRequest(t, owner)
	if _, err := h.server.IssueRefreshToken(context.Background(), server.IssueRefreshTokenRequest{
		GrantType: preAuthorizedCodeGrant, Client: attested, Binding: binding,
		Subject: mustSubjectID(t, "holder-1"), Scope: []string{"accounts"},
	}); err != nil {
		t.Fatalf("IssueRefreshToken: %v", err)
	}

	n, err := h.server.RevokeSubjectGrants(context.Background(), mustSubjectID(t, "user-1"))
	if err != nil || n != 2 {
		t.Fatalf("RevokeSubjectGrants(user-1) = %d, %v, want 2", n, err)
	}
	for _, token := range []string{first, second} {
		if _, err := owner.refresh(token); err == nil {
			t.Error("a revoked grant's refresh token still refreshes")
		}
	}
	if left := listGrants(t, h, "user-1"); len(left) != 0 {
		t.Errorf("ListGrants(user-1) after = %+v, want none", left)
	}
	if others := listGrants(t, h, "holder-1"); len(others) != 1 {
		t.Errorf("ListGrants(holder-1) = %d grants, want its one left alone", len(others))
	}
}

// TestRevokeSubjectGrantsReportsFailures: a registry it can't read fails
// at once, and a revocation failing part way reports how many it
// revoked, leaving the rest listed for a retry.
func TestRevokeSubjectGrantsReportsFailures(t *testing.T) {
	t.Run("list", func(t *testing.T) {
		h := stubRegistryHarness(t, &stubRegistry{listErr: errors.New("registry down")})
		if n, err := h.server.RevokeSubjectGrants(context.Background(), mustSubjectID(t, "user-1")); err == nil || n != 0 {
			t.Fatalf("RevokeSubjectGrants = %d, %v, want 0 and an error", n, err)
		}
	})
	t.Run("part way", func(t *testing.T) {
		registry := &stubRegistry{deleteErr: errors.New("registry down")}
		h := stubRegistryHarness(t, registry)
		registry.entries = []storage.GrantEntry{registryEntry(t, h, "k", testIssuer, "user-1", h.now, nil)}
		if n, err := h.server.RevokeSubjectGrants(context.Background(), mustSubjectID(t, "user-1")); err == nil || n != 0 {
			t.Fatalf("RevokeSubjectGrants = %d, %v, want 0 and an error", n, err)
		}
	})
}

// deleteRecordingRegistry records the keys DeleteGrant is called with.
type deleteRecordingRegistry struct {
	*memstore.GrantRegistry
	deleted *[]string
}

func (r deleteRecordingRegistry) DeleteGrant(ctx context.Context, key string) error {
	*r.deleted = append(*r.deleted, key)
	return r.GrantRegistry.DeleteGrant(ctx, key)
}

// TestCodeReuseForgetsTheGrant: reusing an authorization code revokes
// the refresh token it was exchanged for, and removes its grant from the
// registry, so a "connected apps" page doesn't list it.
func TestCodeReuseForgetsTheGrant(t *testing.T) {
	var deleted []string
	h, owner := registryHarness(t, deleteRecordingRegistry{memstore.NewGrantRegistry(), &deleted})
	code := owner.attestedCode()
	if _, err := owner.exchangeCode(code, testCodeVerifier); err != nil {
		t.Fatalf("first exchange: %v", err)
	}
	listed := listGrants(t, h, "user-1")
	if len(listed) != 1 {
		t.Fatalf("ListGrants = %d grants, want 1", len(listed))
	}
	if _, err := owner.exchangeCode(code, testCodeVerifier); err == nil {
		t.Fatal("reusing the code succeeded")
	}
	if !slices.Contains(deleted, listed[0].ID) {
		t.Errorf("DeleteGrant calls = %v, want the reused code's grant %q", deleted, listed[0].ID)
	}
}

// TestRevokeSubjectGrantsKeepsGoing: an unreadable entry, or a grant
// that fails to revoke, doesn't stop the rest being revoked; every
// failure is reported, with how many were revoked.
func TestRevokeSubjectGrantsKeepsGoing(t *testing.T) {
	registry := &stubRegistry{}
	h := stubRegistryHarness(t, registry)
	registry.entries = []storage.GrantEntry{
		{Key: "bad", ClientID: testClientID, Record: json.RawMessage(`{`), ExpiresAt: h.now.Add(time.Hour)},
		registryEntry(t, h, "good", testIssuer, "user-1", h.now, nil),
	}
	n, err := h.server.RevokeSubjectGrants(context.Background(), mustSubjectID(t, "user-1"))
	if n != 1 || err == nil {
		t.Fatalf("RevokeSubjectGrants = %d, %v, want 1 revoked and the unreadable entry reported", n, err)
	}
	if !slices.Contains(registry.deleted, registryKey("good")) {
		t.Errorf("deleted = %v, want the readable grant revoked", registry.deleted)
	}
	// One that fails to revoke doesn't stop the next either.
	registry.entries = []storage.GrantEntry{
		registryEntry(t, h, "first", testIssuer, "user-1", h.now, nil),
		registryEntry(t, h, "second", testIssuer, "user-1", h.now.Add(time.Second), nil),
	}
	registry.deleted, registry.deleteErr = nil, errors.New("registry down")
	if n, err := h.server.RevokeSubjectGrants(context.Background(), mustSubjectID(t, "user-1")); n != 0 || err == nil || len(registry.deleted) != 2 {
		t.Fatalf("RevokeSubjectGrants = %d, %v after %d deletes, want 0, an error, and both attempted", n, err, len(registry.deleted))
	}
}

// TestRevokeListedGrantPastAnUnreadableEntry: a readable grant is
// revocable though another of the subject's entries can't be read; an
// ID not among the readable ones reports the unreadable entry rather
// than claiming it isn't listed.
func TestRevokeListedGrantPastAnUnreadableEntry(t *testing.T) {
	registry := &stubRegistry{}
	h := stubRegistryHarness(t, registry)
	registry.entries = []storage.GrantEntry{
		{Key: "bad", ClientID: testClientID, Record: json.RawMessage(`{`), ExpiresAt: h.now.Add(time.Hour)},
		registryEntry(t, h, "good", testIssuer, "user-1", h.now, nil),
	}
	if err := h.server.RevokeListedGrant(context.Background(), mustSubjectID(t, "user-1"), registryKey("good")); err != nil {
		t.Fatalf("RevokeListedGrant(readable) = %v, want nil", err)
	}
	if err := h.server.RevokeListedGrant(context.Background(), mustSubjectID(t, "user-1"), "bad"); err == nil || errors.Is(err, server.ErrGrantNotListed) {
		t.Fatalf("RevokeListedGrant(unreadable) = %v, want the unreadable entry reported", err)
	}
}

// undeletableRegistry records and lists grants, but fails every
// DeleteGrant.
type undeletableRegistry struct{ *memstore.GrantRegistry }

func (undeletableRegistry) DeleteGrant(context.Context, string) error {
	return errors.New("registry down")
}

// racingRegistry deletes each grant's entry as it's recorded, as a
// revocation running between recordGrant and CreateRefreshToken does.
type racingRegistry struct{ *memstore.GrantRegistry }

func (r racingRegistry) RecordGrant(ctx context.Context, entry storage.NewGrantEntry) error {
	if err := r.GrantRegistry.RecordGrant(ctx, entry); err != nil {
		return err
	}
	return r.DeleteGrant(ctx, entry.Key)
}

// listFailsAfterRecord lists nothing it can answer for.
type listFailsAfterRecord struct{ *memstore.GrantRegistry }

func (listFailsAfterRecord) ListGrants(context.Context, storage.GrantListing) ([]storage.GrantEntry, error) {
	return nil, errors.New("registry down")
}

// tombstoneKinds are the two GrantStore behaviours a revocation of a
// refresh token not stored yet meets (fakeGrantStore.noTombstones): one
// that keeps the revocation, so the token is refused once stored, as
// storage.GrantStore requires, and one that forgets it.
var tombstoneKinds = map[string]bool{"tombstones": false, "no tombstones": true}

// TestGrantRevokedWhileIssuedIssuesNoToken: a grant whose registry entry
// is gone by the time its refresh token is stored, revoked in between,
// gets no refresh token: the token is withdrawn rather than issued
// unlisted, where RevokeSubjectGrants couldn't find it — with a
// GrantStore that keeps revocations of tokens not yet stored and one
// that doesn't.
func TestGrantRevokedWhileIssuedIssuesNoToken(t *testing.T) {
	for kind, noTombstones := range tombstoneKinds {
		for name, registry := range map[string]func() storage.GrantRegistry{
			"entry gone":         func() storage.GrantRegistry { return racingRegistry{memstore.NewGrantRegistry()} },
			"registry can't say": func() storage.GrantRegistry { return listFailsAfterRecord{memstore.NewGrantRegistry()} },
		} {
			t.Run(kind+"/"+name, func(t *testing.T) {
				h, owner := registryHarness(t, registry())
				h.grants.noTombstones = noTombstones
				attested, binding := embedderTokenRequest(t, owner)
				before := len(h.grants.refreshTokens)
				if _, err := h.server.IssueRefreshToken(context.Background(), server.IssueRefreshTokenRequest{
					GrantType: preAuthorizedCodeGrant, Client: attested, Binding: binding,
					Subject: mustSubjectID(t, "holder-1"), Scope: []string{"accounts"},
				}); err == nil {
					t.Fatal("IssueRefreshToken = nil error, want the issuance refused")
				}
				checkNoLiveRefreshTokenSince(t, h, before)
			})
		}
	}
}

// checkNoLiveRefreshTokenSince checks h's GrantStore redeems none of
// the refresh tokens created after the first before, and that there is
// one.
func checkNoLiveRefreshTokenSince(t *testing.T, h harness, before int) {
	t.Helper()
	h.grants.mu.Lock()
	created := slices.Clone(h.grants.refreshTokens[before:])
	h.grants.mu.Unlock()
	for _, tok := range created {
		if _, err := h.grants.RedeemRefreshToken(context.Background(), storage.RefreshTokenRedemption{TokenHash: tok.TokenHash}); err == nil {
			t.Error("the refresh token created for the revoked grant is still live")
		}
	}
	if len(created) == 0 {
		t.Error("no refresh token was created, so the race wasn't exercised")
	}
}

// TestGrantRevokedWhileIssuedWithdrawalFails: a refresh token that can't
// be withdrawn still isn't issued: both failures are reported.
func TestGrantRevokedWhileIssuedWithdrawalFails(t *testing.T) {
	for kind, noTombstones := range tombstoneKinds {
		t.Run(kind, func(t *testing.T) {
			h, owner := registryHarness(t, racingRegistry{memstore.NewGrantRegistry()})
			h.grants.noTombstones = noTombstones
			h.grants.failRevokeRefresh = errors.New("grants down")
			attested, binding := embedderTokenRequest(t, owner)
			_, err := h.server.IssueRefreshToken(context.Background(), server.IssueRefreshTokenRequest{
				GrantType: preAuthorizedCodeGrant, Client: attested, Binding: binding,
				Subject: mustSubjectID(t, "holder-1"), Scope: []string{"accounts"},
			})
			if err == nil || !strings.Contains(err.Error(), "grants down") {
				t.Fatalf("IssueRefreshToken = %v, want the withdrawal failure reported", err)
			}
		})
	}
}

// keyRecordingRegistry records the GrantListing.Key of each listing,
// and with ignoreKey lists every one of the subject's entries anyway, as
// a store written before Key existed would.
type keyRecordingRegistry struct {
	*memstore.GrantRegistry
	ignoreKey bool
	keys      *[]string
}

func (r keyRecordingRegistry) ListGrants(ctx context.Context, listing storage.GrantListing) ([]storage.GrantEntry, error) {
	*r.keys = append(*r.keys, listing.Key)
	if r.ignoreKey {
		listing.Key = ""
	}
	return r.GrantRegistry.ListGrants(ctx, listing)
}

// TestRefreshTokenIssuanceConfirmsItsOwnEntry: confirming a refresh
// token's grant is still recorded asks for its own entry by key, so its
// cost doesn't grow with the user's other grants, and still issues the
// token from a store that ignores the key and lists them all.
func TestRefreshTokenIssuanceConfirmsItsOwnEntry(t *testing.T) {
	for name, ignoreKey := range map[string]bool{"store honours Key": false, "store ignores Key": true} {
		t.Run(name, func(t *testing.T) {
			var keys []string
			h, owner := registryHarness(t, keyRecordingRegistry{memstore.NewGrantRegistry(), ignoreKey, &keys})
			owner.issueRefreshToken()
			owner.issueRefreshToken()
			if len(keys) != 2 || keys[0] == "" || keys[1] == "" || keys[0] == keys[1] {
				t.Fatalf("issuance listed with keys %q, want each its own entry's key", keys)
			}
			if grants := listGrants(t, h, "user-1"); len(grants) != 2 {
				t.Fatalf("ListGrants(user-1) = %d grants, want 2", len(grants))
			}
		})
	}
}

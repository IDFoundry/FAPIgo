package server_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// registryHarness is newRevocationHarness rebuilt with registry as
// Dependencies.GrantRegistry, and an attested instance of its client.
func registryHarness(t *testing.T, registry storage.GrantRegistry) (harness, *attestedInstance) {
	t.Helper()
	attesterKey := generateKey(t)
	h := newRevocationHarness(t, attesterKey)
	deps := h.deps
	deps.GrantRegistry = registry
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
func registryEntry(t *testing.T, h harness, key, issuer, subject string, issuedAt time.Time, extra map[string]any) storage.GrantEntry {
	t.Helper()
	record := map[string]any{"v": 1, "iss": issuer, "rth": make([]byte, 32), "sub": subject, "issued_at": issuedAt}
	for k, v := range extra {
		record[k] = v
	}
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	return storage.GrantEntry{Key: key, ClientID: testClientID, Record: raw, ExpiresAt: h.now.Add(time.Hour)}
}

func stubRegistryHarness(t *testing.T, registry *stubRegistry) harness {
	t.Helper()
	h, _ := registryHarness(t, registry)
	return h
}

// TestListGrantsReadsEntries: entries are listed oldest first, with
// their authorization details, and one written by another issuer, for
// another subject or past its expiry is left out.
func TestListGrantsReadsEntries(t *testing.T) {
	registry := &stubRegistry{}
	h := stubRegistryHarness(t, registry)
	expired := registryEntry(t, h, "expired", testIssuer, "user-1", h.now, nil)
	expired.ExpiresAt = h.now
	registry.entries = []storage.GrantEntry{
		registryEntry(t, h, "newer", testIssuer, "user-1", h.now, nil),
		registryEntry(t, h, "older", testIssuer, "user-1", h.now.Add(-time.Hour), map[string]any{
			"authorization_details": []map[string]any{{"type": "payment", "amount": "SGD 5"}},
		}),
		registryEntry(t, h, "foreign", "https://other-as.example", "user-1", h.now, nil),
		registryEntry(t, h, "another subject", testIssuer, "user-2", h.now, nil),
		expired,
	}
	grants := listGrants(t, h, "user-1")
	if len(grants) != 2 || grants[0].ID != "older" || grants[1].ID != "newer" {
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
			if err := h.server.RevokeListedGrant(context.Background(), mustSubjectID(t, "user-1"), "k"); err == nil || errors.Is(err, server.ErrGrantNotListed) {
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
	if err := h.server.RevokeListedGrant(context.Background(), mustSubjectID(t, "user-1"), "k"); err == nil {
		t.Fatal("RevokeListedGrant with the registry down = nil error, want error")
	}
	if len(registry.deleted) != 1 {
		t.Errorf("DeleteGrant called %d times, want once", len(registry.deleted))
	}
}

// TestRevokeListedGrantRefusesAnEntryWithoutItsToken: an entry whose
// refresh token hash is missing can't be revoked as listed.
func TestRevokeListedGrantRefusesAnEntryWithoutItsToken(t *testing.T) {
	registry := &stubRegistry{}
	h := stubRegistryHarness(t, registry)
	registry.entries = []storage.GrantEntry{registryEntry(t, h, "k", testIssuer, "user-1", h.now, map[string]any{"rth": []byte{1, 2}})}
	if err := h.server.RevokeListedGrant(context.Background(), mustSubjectID(t, "user-1"), "k"); err == nil || errors.Is(err, server.ErrGrantNotListed) {
		t.Fatalf("RevokeListedGrant(no refresh token hash) = %v, want an error naming it", err)
	}
	if len(registry.deleted) != 0 {
		t.Error("the entry was deleted though its refresh token wasn't revoked")
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
			if err := h.server.RevokeListedGrant(context.Background(), mustSubjectID(t, "user-1"), "k"); err == nil {
				t.Fatal("RevokeListedGrant = nil error, want the failure")
			}
			if len(registry.deleted) != 0 {
				t.Error("the entry was deleted though revoking it failed")
			}
		})
	}
}

// TestRevokeTokenReportsARegistryFailure: a refresh token revoked at the
// revocation endpoint whose registry entry couldn't be removed is a
// server error, so the client retries.
func TestRevokeTokenReportsARegistryFailure(t *testing.T) {
	_, owner := registryHarness(t, &stubRegistry{deleteErr: errors.New("registry down")})
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

package server_test

import (
	"context"
	"errors"
	"strings"
	"testing"

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

package server_test

import (
	"context"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// TestEmbedderGrantDoesNotDeriveSectorFromRedirectURIs: an attested
// client served through an embedder's own grant (IssueAccessToken) has
// no redirect proving it controls its redirect URIs' host, so it derives
// no sector from them. One whose redirect URIs name another relying
// party's host gets no pairwise sub at all rather than that relying
// party's, and one with its own Sector gets a sub of its own.
func TestEmbedderGrantDoesNotDeriveSectorFromRedirectURIs(t *testing.T) {
	attesterKey := generateKey(t)
	h := newAttestationHarness(t, time.Now(), attesterKey, server.RegisteredAttesterKeys{}, func(cfg *server.Config, c *storage.RegisteredClientConfig) {
		cfg.AdditionalGrantTypes = []string{preAuthorizedCodeGrant}
		c.AllowsClientCredentialsGrant = false
		// Its redirect URI is on rp.example, the victim's host; no Sector.
	})
	victim := storage.RegisteredClientConfig{
		ID:                       "victim-rp",
		RedirectURIs:             []fapi.RegisteredRedirectURI{"https://rp.example/cb"},
		ClientAssertionAlgorithm: fapi.ES256,
		RequestObjectAlgorithm:   fapi.ES256,
		AllowedScopes:            []string{"openid"},
	}
	register(t, h, victim)
	h.cfg.Subjects = server.SubjectConfig{
		Default: fapi.SubjectTypePairwise, Enforcement: server.SubjectTypesPerClient,
		Prefix: mustPrefix(t, testPairwisePrefix),
	}
	h.deps.PairwiseSubjects = reversiblePairwise(t)
	srv, err := server.New(h.cfg, h.deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h.server = srv

	instance := &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}
	attested, binding := embedderTokenRequest(t, instance)
	if got := attested.Client.Sector(); got != "" {
		t.Fatalf("the attested client derived sector %q from its redirect URIs, want none", got)
	}
	issued, err := h.server.IssueAccessToken(context.Background(), server.IssueAccessTokenRequest{
		GrantType: preAuthorizedCodeGrant, Client: attested, Binding: binding,
		Subject: mustSubjectID(t, "alice"), Scope: []string{"accounts"},
	})
	if err == nil {
		t.Fatalf("IssueAccessToken for a pairwise client with no sector = %+v, want an error", issued)
	}
}

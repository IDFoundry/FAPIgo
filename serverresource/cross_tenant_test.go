package serverresource_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/serverresource"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// TestVerifierRefusesAnotherTenantsAccessToken covers two tenants
// (issuers A and B) sharing their access token store, or their signing
// key, and one API both name as a resource: whatever the token format,
// tenant B's verifier refuses a token tenant A issued to its user, which
// it would otherwise take for tenant B's user with the same subject,
// and tenant A's verifier accepts it.
func TestVerifierRefusesAnotherTenantsAccessToken(t *testing.T) {
	const api = "https://api.saas.example"
	now := time.Now()
	ctx := context.Background()
	tenant := func(issuer string) server.Config {
		cfg := serverConfig(t)
		iss, err := fapi.ParseIssuerURL(issuer)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Issuer = iss
		cfg.Resources = []string{api}
		return cfg
	}
	cfgA, cfgB := tenant("https://tenant-a.idp.example"), tenant("https://tenant-b.idp.example")
	cert := clientCertificate(t)
	tp := sha256.Sum256(cert.Raw)

	for name, tokens := range map[string]server.AccessTokenIssuer{
		"opaque": server.OpaqueAccessTokens{Store: memstore.NewAccessTokenStore()},
		"jwt":    jwtAccessTokens(t),
	} {
		t.Run(name, func(t *testing.T) {
			tok, _, err := tokens.IssueAccessToken(ctx, server.AccessTokenParams{
				ClientID: "shared-client", Subject: "alice", Scope: []string{"accounts"},
				Thumbprint:      base64.RawURLEncoding.EncodeToString(tp[:]),
				SenderConstrain: storage.SenderConstrainMTLS,
				Issuer:          cfgA.Issuer.String(), Audience: api, Audiences: []string{api},
				Now: now, Lifetime: time.Minute, Random: rand.Reader,
			})
			if err != nil {
				t.Fatal(err)
			}
			req := resource.VerifyRequest{
				Method: "GET", URL: &url.URL{Scheme: "https", Host: "api.saas.example", Path: "/accounts"},
				Authorization: "Bearer " + tok, PeerCertificate: cert,
			}
			verify := func(cfg server.Config) (resource.AuthorizationContext, error) {
				v, err := serverresource.NewVerifier(cfg, serverDependencies(t, tokens, now), withURLs(t, serverresource.Options{Resource: api}))
				if err != nil {
					t.Fatalf("NewVerifier: %v", err)
				}
				return v.Verify(ctx, req)
			}
			if _, err := verify(cfgB); err == nil {
				t.Fatal("tenant B's verifier accepted tenant A's access token")
			}
			authz, err := verify(cfgA)
			if err != nil {
				t.Fatalf("tenant A's verifier refused its own access token: %v", err)
			}
			if authz.Issuer != cfgA.Issuer.String() {
				t.Errorf("Issuer = %q, want %q", authz.Issuer, cfgA.Issuer.String())
			}
		})
	}
}

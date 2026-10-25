package server_test

import (
	"context"
	"crypto/ecdsa"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/keys/ephemeral"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// TestAutomaticRegistrationStaticClientRefusesFederationKey: a
// statically registered client whose client_id is also an Entity
// Identifier resolving under one of the server's Automatic Registration
// Trust Anchors authenticates with its static keys only. Its static
// registration grants client_credentials and a scope automatic
// registration doesn't; a client assertion signed with the key its
// federation metadata publishes (rp-oidc — a key any superior in its
// Trust Chain can set) must not authenticate as it.
func TestAutomaticRegistrationStaticClientRefusesFederationKey(t *testing.T) {
	f := setupAutomaticRegistrationFixture(t, testRedirectURI)

	staticKey := generateKey(t)
	staticClient, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID:                           fapi.ClientID(f.rpID),
		ClientAuthMethod:             storage.ClientAuthMethodPrivateKeyJWT,
		ClientAssertionAlgorithm:     fapi.ES256,
		AllowedScopes:                []string{"accounts", "payments:admin"},
		AllowsClientCredentialsGrant: true,
	})
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}
	staticKeys, err := ephemeral.NewClientKeySource(nil, []ephemeral.ClientKeySpec{{ClientID: fapi.ClientID(f.rpID), JWKS: fedJWKS(t, "static-kid", staticKey)}})
	if err != nil {
		t.Fatalf("ephemeral.NewClientKeySource: %v", err)
	}

	srv := newAutomaticRegistrationTestServer(t, f, func(cfg *server.Config, deps *server.Dependencies) {
		cfg.ClientCredentialsGrant = true
		cfg.AutomaticRegistration.AllowsClientCredentialsGrant = false
		deps.Clients = &fakeClientRepository{clients: map[fapi.ClientID]storage.RegisteredClient{fapi.ClientID(f.rpID): staticClient}}
		deps.ClientKeys = staticKeys
	})

	request := func(signer *ecdsa.PrivateKey, kid string) error {
		t.Helper()
		assertion, err := clientassertion.CreateAssertion(clientassertion.AssertionRequest{
			Signer: signer, Algorithm: fapi.ES256, KeyID: kid,
			ClientID: f.rpID, Audience: testIssuer, Now: f.now, Lifetime: 30 * time.Second,
		})
		if err != nil {
			t.Fatalf("CreateAssertion: %v", err)
		}
		_, err = srv.RequestClientCredentialsToken(context.Background(), server.ClientCredentialsTokenRequest{
			HTTP: server.FormRequest{Parameters: []server.FormParameter{
				formParam("grant_type", "client_credentials"),
				formParam("client_assertion", assertion),
				formParam("client_assertion_type", clientassertion.AssertionType),
				formParam("scope", "payments:admin"),
			}},
			DPoPProofs: []string{createDPoPProof(t, generateKey(t), f.now)},
		})
		return err
	}

	if err := request(staticKey, "static-kid"); err != nil {
		t.Fatalf("assertion signed with the static key: %v, want a token", err)
	}
	if err := request(f.rpOIDCKey, "rp-oidc"); err == nil {
		t.Fatalf("assertion signed with the federation-published key authenticated as the statically registered client, want invalid_client")
	}
}

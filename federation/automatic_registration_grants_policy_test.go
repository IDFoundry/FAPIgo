package federation_test

import (
	"context"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/federation"
	"github.com/idfoundry/fapigo/storage"
)

// grantsPolicyCase is one TestAutomaticRegistrationNarrowsGrantsByResolvedMetadata
// case: the RP's own published scope/grant_types, the policy its superior
// sets on them ("" for none), and what the registration must allow.
type grantsPolicyCase struct {
	members           map[string]any
	policy            string
	wantErr           bool
	wantScopes        map[string]bool
	wantClientCreds   bool
	wantCIBAPermitted bool
}

// TestAutomaticRegistrationNarrowsGrantsByResolvedMetadata checks that
// the operator's AllowedScopes, AllowsClientCredentialsGrant and
// AllowsCIBA are narrowed by the RP's resolved scope and grant_types —
// its metadata after every superior's metadata policy (OpenID Federation
// 1.0 §6.1) — and that leaving either out narrows nothing.
func TestAutomaticRegistrationNarrowsGrantsByResolvedMetadata(t *testing.T) {
	base := func(extra map[string]any) map[string]any {
		m := map[string]any{
			"redirect_uris":                                  []string{"https://rp.example.org/cb"},
			"token_endpoint_auth_method":                     "private_key_jwt",
			"token_endpoint_auth_signing_alg":                "ES256",
			"backchannel_authentication_request_signing_alg": "ES256",
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	cases := map[string]grantsPolicyCase{
		"superior's subset_of narrows scope and grant_types": {
			members: base(map[string]any{
				"scope":       "openid payments",
				"grant_types": []string{"authorization_code", "client_credentials", "urn:openid:params:grant-type:ciba"},
			}),
			policy:     `{"openid_relying_party":{"scope":{"subset_of":["openid"]},"grant_types":{"subset_of":["authorization_code"]}}}`,
			wantScopes: map[string]bool{"openid": true, "payments": false},
		},
		"absent scope and grant_types narrow nothing": {
			members:           base(nil),
			wantScopes:        map[string]bool{"openid": true, "payments": true},
			wantClientCreds:   true,
			wantCIBAPermitted: true,
		},
		"listed grants and scopes are kept": {
			members: base(map[string]any{
				"scope":       "openid payments accounts",
				"grant_types": []string{"client_credentials", "urn:openid:params:grant-type:ciba"},
			}),
			wantScopes:        map[string]bool{"openid": true, "payments": true, "accounts": false},
			wantClientCreds:   true,
			wantCIBAPermitted: true,
		},
		"scope with none of the allowed scopes fails": {
			members: base(map[string]any{"scope": "accounts"}),
			wantErr: true,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			client, err := resolveWithGrantsPolicy(t, tc)
			if tc.wantErr {
				if err == nil {
					t.Fatal("ResolveClient succeeded, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveClient: %v", err)
			}
			checkGrants(t, client, tc)
		})
	}
}

func resolveWithGrantsPolicy(t *testing.T, tc grantsPolicyCase) (storage.RegisteredClient, error) {
	t.Helper()
	f := setupAutomaticRegistrationFixture(t, rpMetadataMembers(t, tc.members))
	if tc.policy != "" {
		f = setupAutomaticRegistrationFixtureWithPolicy(t, rpMetadataMembers(t, tc.members), mustPolicy(t, tc.policy))
	}
	cfg := validAutomaticRegistrationConfig()
	cfg.AllowedScopes = []string{"openid", "payments"}
	cfg.AllowsClientCredentialsGrant = true
	cfg.AllowsCIBA = true
	repo, err := federation.NewAutomaticClientRepository(alwaysFailsRepository{}, f.newResolver(t), f.fetcher, cfg, fixedClock{now: f.now})
	if err != nil {
		t.Fatalf("NewAutomaticClientRepository: %v", err)
	}
	return repo.ResolveClient(context.Background(), fapi.ClientID(f.rpID))
}

func checkGrants(t *testing.T, client storage.RegisteredClient, tc grantsPolicyCase) {
	t.Helper()
	var allowed []string
	for scope, want := range tc.wantScopes {
		if got := client.AllowsScope(scope); got != want {
			t.Errorf("AllowsScope(%q) = %v, want %v", scope, got, want)
		}
		if want {
			allowed = append(allowed, scope)
		}
	}
	// The scope bound a request from the client gets counts the scopes
	// the operator's allowlist narrowed to, not the RP's own metadata.
	if got, want := client.AllowedScopesLength(), len(strings.Join(allowed, " ")); got != want {
		t.Errorf("AllowedScopesLength() = %d, want %d", got, want)
	}
	if got := client.AllowsClientCredentialsGrant(); got != tc.wantClientCreds {
		t.Errorf("AllowsClientCredentialsGrant() = %v, want %v", got, tc.wantClientCreds)
	}
	if _, got := client.BackchannelAuthenticationRequestAlgorithm(); got != tc.wantCIBAPermitted {
		t.Errorf("BackchannelAuthenticationRequestAlgorithm permitted = %v, want %v", got, tc.wantCIBAPermitted)
	}
}

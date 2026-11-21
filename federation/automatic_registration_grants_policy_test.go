package federation_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/federation"
	intfed "github.com/idfoundry/fapigo/internal/federation"
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

// setupAutomaticRegistrationFixtureUnderIntermediate is
// setupAutomaticRegistrationFixtureWithPolicy with an Intermediate
// between the Trust Anchor and the RP: the Trust Anchor's Subordinate
// Statement about the Intermediate carries taPolicy and the
// Intermediate's about the RP carries imPolicy (either may be nil), so
// the RP's metadata is resolved under the two merged (OpenID Federation
// 1.0 §6.1.4.1).
func setupAutomaticRegistrationFixtureUnderIntermediate(t *testing.T, metadataFn func(rpID string, rpOIDCKey *ecdsa.PrivateKey) json.RawMessage, taPolicy, imPolicy intfed.MetadataPolicy) *automaticRegistrationFixture {
	t.Helper()
	now := time.Now()
	taKey, imKey, rpFedKey, rpOIDCKey := generateKey(t), generateKey(t), generateKey(t), generateKey(t)
	taJWKS, imJWKS, rpFedJWKS := jwksFor(t, "ta", taKey), jwksFor(t, "im", imKey), jwksFor(t, "rp-fed", rpFedKey)

	taMux, imMux, rpMux := http.NewServeMux(), http.NewServeMux(), http.NewServeMux()
	taServer, imServer, rpServer := httptest.NewTLSServer(taMux), httptest.NewTLSServer(imMux), httptest.NewTLSServer(rpMux)
	for _, s := range []*httptest.Server{taServer, imServer, rpServer} {
		t.Cleanup(s.Close)
	}
	taID, imID, rpID := taServer.URL, imServer.URL, rpServer.URL

	sign := func(p intfed.CreateParams) string {
		t.Helper()
		p.Algorithm, p.Now, p.Lifetime = fapi.ES256, now, time.Hour
		token, err := intfed.Create(p)
		if err != nil {
			t.Fatalf("intfed.Create: %v", err)
		}
		return token
	}
	taMux.HandleFunc("/.well-known/openid-federation", serveStatement(sign(intfed.CreateParams{
		Signer: taKey, KeyID: "ta", Issuer: taID, Subject: taID, JWKS: taJWKS,
		Metadata: federationEntityMetadata(t, taID+"/fetch"),
	})))
	taMux.HandleFunc("/fetch", serveFetch(map[string]string{imID: sign(intfed.CreateParams{
		Signer: taKey, KeyID: "ta", Issuer: taID, Subject: imID, JWKS: imJWKS, MetadataPolicy: taPolicy,
	})}))
	imMux.HandleFunc("/.well-known/openid-federation", serveStatement(sign(intfed.CreateParams{
		Signer: imKey, KeyID: "im", Issuer: imID, Subject: imID, JWKS: imJWKS,
		AuthorityHints: []string{taID}, Metadata: federationEntityMetadata(t, imID+"/fetch"),
	})))
	imMux.HandleFunc("/fetch", serveFetch(map[string]string{rpID: sign(intfed.CreateParams{
		Signer: imKey, KeyID: "im", Issuer: imID, Subject: rpID, JWKS: rpFedJWKS, MetadataPolicy: imPolicy,
	})}))
	rpMux.HandleFunc("/.well-known/openid-federation", serveStatement(sign(intfed.CreateParams{
		Signer: rpFedKey, KeyID: "rp-fed", Issuer: rpID, Subject: rpID, JWKS: rpFedJWKS,
		AuthorityHints: []string{imID},
		Metadata:       map[string]json.RawMessage{"openid_relying_party": metadataFn(rpID, rpOIDCKey)},
	})))

	return &automaticRegistrationFixture{
		taID: taID, rpID: rpID, taKey: taKey, taJWKS: taJWKS,
		rpFedKey: rpFedKey, rpOIDCKey: rpOIDCKey,
		fetcher: fetcherFor(t, taServer, imServer, rpServer), now: now, rpMux: rpMux,
	}
}

// policyOrNil is mustPolicy, or nil for "".
func policyOrNil(t *testing.T, raw string) intfed.MetadataPolicy {
	t.Helper()
	if raw == "" {
		return nil
	}
	return mustPolicy(t, raw)
}

// TestAutomaticRegistrationHoldsGrantsToGrantTypesPolicy: a superior's
// subset_of (or value) on grant_types withholds client_credentials and
// CIBA from an RP that leaves grant_types out — which the policy's
// operators leave absent — as it does from one that publishes it,
// wherever in the Trust Chain the policy is, and also when an
// Intermediate's value null removes what the RP published. The operator
// allows both grants; an RP under no grant_types policy still gets them.
func TestAutomaticRegistrationHoldsGrantsToGrantTypesPolicy(t *testing.T) {
	const cibaGrant = "urn:openid:params:grant-type:ciba"
	policy := func(grantTypes string) string {
		return `{"openid_relying_party":{"grant_types":` + grantTypes + `}}`
	}
	// The shape OpenID Federation 1.0's own examples use (§6.1.5).
	codeFlowOnly := policy(`{"subset_of":["authorization_code","refresh_token"]}`)
	for _, tc := range []struct {
		name               string
		taPolicy, imPolicy string
		grantTypes         []string // the RP's own; nil leaves grant_types out
		wantClientCreds    bool
		wantCIBA           bool
	}{
		{name: "Trust Anchor's subset_of", taPolicy: codeFlowOnly},
		{name: "Trust Anchor's subset_of with superset_of",
			taPolicy: policy(`{"subset_of":["authorization_code","refresh_token"],"superset_of":["authorization_code"]}`)},
		{name: "Intermediate's subset_of", imPolicy: codeFlowOnly},
		{name: "Intermediate's value null under the Trust Anchor's subset_of",
			taPolicy: codeFlowOnly, imPolicy: policy(`{"value":null}`), grantTypes: []string{"authorization_code"}},
		{name: "subset_of, grant_types published", taPolicy: codeFlowOnly, grantTypes: []string{"authorization_code", "client_credentials", cibaGrant}},
		{name: "value", taPolicy: policy(`{"value":["authorization_code","client_credentials"]}`), wantClientCreds: true},
		{name: "subset_of permitting both",
			taPolicy:        policy(`{"subset_of":["authorization_code","client_credentials","` + cibaGrant + `"]}`),
			wantClientCreds: true, wantCIBA: true},
		{name: "value null alone", imPolicy: policy(`{"value":null}`), grantTypes: []string{"authorization_code"},
			wantClientCreds: true, wantCIBA: true},
		{name: "a policy on another parameter only",
			taPolicy:        `{"openid_relying_party":{"token_endpoint_auth_method":{"one_of":["private_key_jwt"]}}}`,
			wantClientCreds: true, wantCIBA: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			members := map[string]any{
				"redirect_uris":                                  []string{"https://rp.example.org/cb"},
				"token_endpoint_auth_method":                     "private_key_jwt",
				"token_endpoint_auth_signing_alg":                "ES256",
				"backchannel_authentication_request_signing_alg": "ES256",
			}
			if tc.grantTypes != nil {
				members["grant_types"] = tc.grantTypes
			}
			f := setupAutomaticRegistrationFixtureUnderIntermediate(t, rpMetadataMembers(t, members), policyOrNil(t, tc.taPolicy), policyOrNil(t, tc.imPolicy))
			cfg := validAutomaticRegistrationConfig()
			cfg.AllowsClientCredentialsGrant = true
			cfg.AllowsCIBA = true
			repo, err := federation.NewAutomaticClientRepository(alwaysFailsRepository{}, f.newResolver(t), f.fetcher, cfg, fixedClock{now: f.now})
			if err != nil {
				t.Fatalf("NewAutomaticClientRepository: %v", err)
			}
			client, err := repo.ResolveClient(context.Background(), fapi.ClientID(f.rpID))
			if err != nil {
				t.Fatalf("ResolveClient: %v", err)
			}
			if got := client.AllowsClientCredentialsGrant(); got != tc.wantClientCreds {
				t.Errorf("AllowsClientCredentialsGrant() = %v, want %v", got, tc.wantClientCreds)
			}
			if _, got := client.BackchannelAuthenticationRequestAlgorithm(); got != tc.wantCIBA {
				t.Errorf("BackchannelAuthenticationRequestAlgorithm permitted = %v, want %v", got, tc.wantCIBA)
			}
		})
	}
}

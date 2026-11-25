package federation_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
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
// 1.0 §6.1) — that leaving scope out narrows nothing, and that leaving
// grant_types out means the authorization code flow alone.
func TestAutomaticRegistrationNarrowsGrantsByResolvedMetadata(t *testing.T) {
	base := func(extra map[string]any) map[string]any {
		m := map[string]any{
			"redirect_uris":                                  []string{"https://rp.example.org/cb"},
			"token_endpoint_auth_method":                     "private_key_jwt",
			"token_endpoint_auth_signing_alg":                "ES256",
			"backchannel_authentication_request_signing_alg": "ES256",
			"backchannel_token_delivery_mode":                "poll",
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
		"absent scope narrows nothing, absent grant_types means the code flow alone": {
			members:    base(nil),
			wantScopes: map[string]bool{"openid": true, "payments": true},
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
		// The policy's operators act only on a scope that is present, so
		// these hold an RP leaving it out to what the policy permits.
		"absent scope under subset_of": {
			members:    base(nil),
			policy:     `{"openid_relying_party":{"scope":{"subset_of":["openid","accounts"]}}}`,
			wantScopes: map[string]bool{"openid": true, "payments": false},
		},
		"absent scope under one_of": {
			members:    base(nil),
			policy:     `{"openid_relying_party":{"scope":{"one_of":["payments","payments accounts"]}}}`,
			wantScopes: map[string]bool{"openid": false, "payments": true},
		},
		"absent scope under subset_of permitting none of the allowed scopes fails": {
			members: base(nil),
			policy:  `{"openid_relying_party":{"scope":{"subset_of":["accounts"]}}}`,
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
// 1.0 §6.1.4.1). The fixture's setTAPolicy changes taPolicy; call it from
// the test that built the fixture.
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
	var taAboutIM atomic.Pointer[string]
	setTAPolicy := func(policy intfed.MetadataPolicy) {
		token := sign(intfed.CreateParams{
			Signer: taKey, KeyID: "ta", Issuer: taID, Subject: imID, JWKS: imJWKS, MetadataPolicy: policy,
		})
		taAboutIM.Store(&token)
	}
	setTAPolicy(taPolicy)
	taMux.HandleFunc("/fetch", func(w http.ResponseWriter, r *http.Request) {
		serveFetch(map[string]string{imID: *taAboutIM.Load()})(w, r)
	})
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
		setTAPolicy: setTAPolicy,
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
// CIBA from an RP that publishes grant_types, wherever in the Trust
// Chain the policy is, and an RP that leaves grant_types out (which the
// policy's operators leave absent) gets neither under it, nor when an
// Intermediate's value null removes what the RP published. The operator
// allows both grants; an RP listing them under a policy permitting them,
// or under no grant_types policy, still gets them, while an
// Intermediate's value null alone removes them with the rest of the RP's
// grant_types, leaving it the authorization code flow.
func TestAutomaticRegistrationHoldsGrantsToGrantTypesPolicy(t *testing.T) {
	const cibaGrant = "urn:openid:params:grant-type:ciba"
	policy := func(grantTypes string) string {
		return `{"openid_relying_party":{"grant_types":` + grantTypes + `}}`
	}
	// The shape OpenID Federation 1.0's own examples use (§6.1.5).
	codeFlowOnly := policy(`{"subset_of":["authorization_code","refresh_token"]}`)
	allGrants := []string{"authorization_code", "client_credentials", cibaGrant}
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
			taPolicy:   policy(`{"subset_of":["authorization_code","client_credentials","` + cibaGrant + `"]}`),
			grantTypes: allGrants, wantClientCreds: true, wantCIBA: true},
		{name: "value null alone", imPolicy: policy(`{"value":null}`), grantTypes: allGrants},
		{name: "a policy on another parameter only",
			taPolicy:   `{"openid_relying_party":{"token_endpoint_auth_method":{"one_of":["private_key_jwt"]}}}`,
			grantTypes: allGrants, wantClientCreds: true, wantCIBA: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, err := resolveWithGrantTypes(t, tc.taPolicy, tc.imPolicy, tc.grantTypes)
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

// resolveWithGrantTypes registers the RP publishing grantTypes (nil
// leaves grant_types out) and poll delivery for CIBA under taPolicy and
// imPolicy (see setupAutomaticRegistrationFixtureUnderIntermediate), with
// the operator allowing client_credentials and CIBA.
func resolveWithGrantTypes(t *testing.T, taPolicy, imPolicy string, grantTypes []string) (storage.RegisteredClient, error) {
	t.Helper()
	members := map[string]any{
		"redirect_uris":                                  []string{"https://rp.example.org/cb"},
		"token_endpoint_auth_method":                     "private_key_jwt",
		"token_endpoint_auth_signing_alg":                "ES256",
		"backchannel_authentication_request_signing_alg": "ES256",
		"backchannel_token_delivery_mode":                "poll",
	}
	if grantTypes != nil {
		members["grant_types"] = grantTypes
	}
	f := setupAutomaticRegistrationFixtureUnderIntermediate(t, rpMetadataMembers(t, members), policyOrNil(t, taPolicy), policyOrNil(t, imPolicy))
	cfg := validAutomaticRegistrationConfig()
	cfg.AllowsClientCredentialsGrant = true
	cfg.AllowsCIBA = true
	repo, err := federation.NewAutomaticClientRepository(alwaysFailsRepository{}, f.newResolver(t), f.fetcher, cfg, fixedClock{now: f.now})
	if err != nil {
		t.Fatalf("NewAutomaticClientRepository: %v", err)
	}
	return repo.ResolveClient(context.Background(), fapi.ClientID(f.rpID))
}

// TestAutomaticRegistrationNarrowsRARTypesByResolvedMetadata: the
// operator's AuthorizationDetailsTypes are narrowed to those the RP's
// resolved authorization_details_types lists — its own after every
// superior's metadata policy — and, when it leaves the parameter out, to
// those a superior's subset_of or value permits. Nothing the RP lists
// itself is ever added, and being left none is no error.
func TestAutomaticRegistrationNarrowsRARTypesByResolvedMetadata(t *testing.T) {
	policy := func(operators string) string {
		return `{"openid_relying_party":{"authorization_details_types":` + operators + `}}`
	}
	accountsOnly := policy(`{"subset_of":["account_information"]}`)
	for _, tc := range []struct {
		name               string
		taPolicy, imPolicy string
		rpTypes            []string // nil leaves authorization_details_types out
		want               []string // the types registered, sorted
	}{
		{name: "no policy, the parameter left out", want: []string{"account_information", "payment"}},
		{name: "no policy, the RP's own list", rpTypes: []string{"payment", "unknown"}, want: []string{"payment"}},
		{name: "no policy, an empty list", rpTypes: []string{}, want: []string{}},
		{name: "value", taPolicy: policy(`{"value":["account_information"]}`), rpTypes: []string{"payment"}, want: []string{"account_information"}},
		{name: "value, the parameter left out", taPolicy: policy(`{"value":["account_information"]}`), want: []string{"account_information"}},
		{name: "value of none", taPolicy: policy(`{"value":[]}`), rpTypes: []string{"payment"}, want: []string{}},
		{name: "subset_of", taPolicy: accountsOnly, rpTypes: []string{"payment"}, want: []string{}},
		{name: "subset_of, the parameter left out", taPolicy: accountsOnly, want: []string{"account_information"}},
		{name: "default", taPolicy: policy(`{"default":["account_information"]}`), want: []string{"account_information"}},
		{name: "Intermediate's value null under the Trust Anchor's subset_of",
			taPolicy: accountsOnly, imPolicy: policy(`{"value":null}`), rpTypes: []string{"payment", "account_information"},
			want: []string{"account_information"}},
		{name: "Intermediate's subset_of", imPolicy: accountsOnly, want: []string{"account_information"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			members := map[string]any{
				"redirect_uris":                   []string{"https://rp.example.org/cb"},
				"token_endpoint_auth_method":      "private_key_jwt",
				"token_endpoint_auth_signing_alg": "ES256",
			}
			if tc.rpTypes != nil {
				members["authorization_details_types"] = tc.rpTypes
			}
			client, err := resolveWithRARTypes(t, tc.taPolicy, tc.imPolicy, members)
			if err != nil {
				t.Fatalf("ResolveClient: %v", err)
			}
			if got := client.AuthorizationDetailsTypes(); !slices.Equal(got, tc.want) {
				t.Errorf("AuthorizationDetailsTypes() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestAutomaticRegistrationRefusesMalformedRARTypes: an
// authorization_details_types that isn't an array of strings is
// malformed metadata, refused like any other, rather than read as
// absent and so narrowing nothing.
func TestAutomaticRegistrationRefusesMalformedRARTypes(t *testing.T) {
	for name, value := range map[string]any{"a string": "payment", "a number in the array": []any{"payment", 1}} {
		t.Run(name, func(t *testing.T) {
			members := map[string]any{
				"redirect_uris":                   []string{"https://rp.example.org/cb"},
				"token_endpoint_auth_method":      "private_key_jwt",
				"token_endpoint_auth_signing_alg": "ES256",
				"authorization_details_types":     value,
			}
			if client, err := resolveWithRARTypes(t, "", "", members); err == nil {
				t.Fatalf("ResolveClient registered %q, want the metadata refused", client.AuthorizationDetailsTypes())
			}
		})
	}
}

// resolveWithRARTypes registers the RP publishing members under
// taPolicy and imPolicy (see setupAutomaticRegistrationFixtureUnderIntermediate),
// with payment and account_information as the operator's RAR types.
func resolveWithRARTypes(t *testing.T, taPolicy, imPolicy string, members map[string]any) (storage.RegisteredClient, error) {
	t.Helper()
	f := setupAutomaticRegistrationFixtureUnderIntermediate(t, rpMetadataMembers(t, members), policyOrNil(t, taPolicy), policyOrNil(t, imPolicy))
	cfg := validAutomaticRegistrationConfig()
	cfg.AuthorizationDetailsTypes = []string{"payment", "account_information"}
	repo, err := federation.NewAutomaticClientRepository(alwaysFailsRepository{}, f.newResolver(t), f.fetcher, cfg, fixedClock{now: f.now})
	if err != nil {
		t.Fatalf("NewAutomaticClientRepository: %v", err)
	}
	return repo.ResolveClient(context.Background(), fapi.ClientID(f.rpID))
}

// TestAutomaticRegistrationWithdrawalTakesEffectWhenTheCacheExpires: a
// Trust Anchor that starts withholding a RAR type and a grant from a
// branch, by policy on the RAR types its RP leaves out and the grant
// types it lists, takes them from the RP's registration once its cached
// registration expires (MaxCacheAge), not before. That is the
// registration the server checks a grant against again on refresh, so
// the RP's refresh tokens for the withdrawn type stop working then too.
func TestAutomaticRegistrationWithdrawalTakesEffectWhenTheCacheExpires(t *testing.T) {
	f := setupAutomaticRegistrationFixtureUnderIntermediate(t, rpMetadataMembers(t, map[string]any{
		"redirect_uris":                   []string{"https://rp.example.org/cb"},
		"grant_types":                     []string{"authorization_code", "client_credentials"},
		"token_endpoint_auth_method":      "private_key_jwt",
		"token_endpoint_auth_signing_alg": "ES256",
	}), nil, nil)
	cfg := validAutomaticRegistrationConfig()
	cfg.AuthorizationDetailsTypes = []string{"payment", "account_information"}
	cfg.AllowsClientCredentialsGrant = true
	cfg.MaxCacheAge = time.Minute
	clock := &steppingClock{now: f.now}
	repo, err := federation.NewAutomaticClientRepository(alwaysFailsRepository{}, f.newResolver(t), f.fetcher, cfg, clock)
	if err != nil {
		t.Fatalf("NewAutomaticClientRepository: %v", err)
	}
	allowed := func() (payment, clientCredentials bool) {
		t.Helper()
		client, err := repo.ResolveClient(context.Background(), fapi.ClientID(f.rpID))
		if err != nil {
			t.Fatalf("ResolveClient: %v", err)
		}
		return client.AllowsAuthorizationDetailsType("payment"), client.AllowsClientCredentialsGrant()
	}

	if payment, clientCredentials := allowed(); !payment || !clientCredentials {
		t.Fatalf("before the policy: payment %v, client_credentials %v; want both", payment, clientCredentials)
	}
	f.setTAPolicy(mustPolicy(t, `{"openid_relying_party":{
		"authorization_details_types":{"subset_of":["account_information"]},
		"grant_types":{"subset_of":["authorization_code","refresh_token"]}}}`))
	clock.now = f.now.Add(cfg.MaxCacheAge - time.Second)
	if payment, clientCredentials := allowed(); !payment || !clientCredentials {
		t.Fatalf("within MaxCacheAge: payment %v, client_credentials %v; want the cached registration's", payment, clientCredentials)
	}
	clock.now = f.now.Add(cfg.MaxCacheAge)
	if payment, clientCredentials := allowed(); payment || clientCredentials {
		t.Errorf("once the cached registration expired: payment %v, client_credentials %v; want both withdrawn", payment, clientCredentials)
	}
}

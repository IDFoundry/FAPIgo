package server_test

import (
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	intfed "github.com/idfoundry/fapigo/internal/federation"
	"github.com/idfoundry/fapigo/internal/requestobject"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// setupBranchFixture builds a Trust Anchor -> Intermediate -> RP
// federation over HTTPS test servers on loopback, for an RP in a branch
// of the federation its superiors restrict: the Trust Anchor's
// Subordinate Statement about the Intermediate carries taPolicy and the
// Intermediate's about the RP carries imPolicy (each a metadata_policy
// claim, "" for none). The RP's openid_relying_party metadata registers
// testRedirectURI, private_key_jwt, and CIBA's signing algorithm and poll
// delivery, plus extra's members; it lists no grant_types unless extra
// does. A server trusting only the Trust Anchor
// (validAutomaticRegistrationServerConfig) registers the RP under both
// policies, merged.
func setupBranchFixture(t *testing.T, taPolicy, imPolicy string, extra map[string]any) *automaticRegistrationFixture {
	t.Helper()
	return setupBranchFixtureOn(t, loopbackFederation{}, taPolicy, imPolicy, extra)
}

// setupBranchFixtureOn is setupBranchFixture with the federation's
// servers on network, which also supplies the fixture's fetcher.
func setupBranchFixtureOn(t *testing.T, network federationNetwork, taPolicy, imPolicy string, extra map[string]any) *automaticRegistrationFixture {
	t.Helper()
	now := time.Now()
	taKey, imKey, rpFedKey, rpOIDCKey := generateKey(t), generateKey(t), generateKey(t), generateKey(t)
	taJWKS, imJWKS, rpFedJWKS := fedJWKS(t, "ta", taKey), fedJWKS(t, "im", imKey), fedJWKS(t, "rp-fed", rpFedKey)

	taMux, imMux, rpMux := http.NewServeMux(), http.NewServeMux(), http.NewServeMux()
	servers := []*httptest.Server{network.serve(t, taMux), network.serve(t, imMux), network.serve(t, rpMux)}
	taID, imID, rpID := servers[0].URL, servers[1].URL, servers[2].URL

	sign := func(p intfed.CreateParams) string {
		t.Helper()
		p.Algorithm, p.Now, p.Lifetime = fapi.ES256, now, time.Hour
		token, err := intfed.Create(p)
		if err != nil {
			t.Fatalf("intfed.Create: %v", err)
		}
		return token
	}
	policy := func(raw string) intfed.MetadataPolicy {
		t.Helper()
		if raw == "" {
			return nil
		}
		var p intfed.MetadataPolicy
		if err := json.Unmarshal([]byte(raw), &p); err != nil {
			t.Fatalf("unmarshal metadata policy: %v", err)
		}
		return p
	}
	fetchEndpoint := func(id string) map[string]json.RawMessage {
		t.Helper()
		raw, err := json.Marshal(map[string]string{"federation_fetch_endpoint": id + "/fetch"})
		if err != nil {
			t.Fatalf("marshal federation_entity metadata: %v", err)
		}
		return map[string]json.RawMessage{"federation_entity": raw}
	}
	rpMetadata := map[string]any{
		"redirect_uris":                                  []string{testRedirectURI},
		"token_endpoint_auth_method":                     "private_key_jwt",
		"token_endpoint_auth_signing_alg":                "ES256",
		"backchannel_token_delivery_mode":                "poll",
		"backchannel_authentication_request_signing_alg": "ES256",
		"jwks": json.RawMessage(fedJWKS(t, "rp-oidc", rpOIDCKey)),
	}
	for k, v := range extra {
		rpMetadata[k] = v
	}
	rpMetadataJSON, err := json.Marshal(rpMetadata)
	if err != nil {
		t.Fatalf("marshal openid_relying_party metadata: %v", err)
	}

	serveToken := func(token string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/entity-statement+jwt")
			w.Write([]byte(token))
		}
	}
	serveFetch := func(sub, token string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("sub") != sub {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			serveToken(token)(w, r)
		}
	}
	taMux.HandleFunc("/.well-known/openid-federation", serveToken(sign(intfed.CreateParams{
		Signer: taKey, KeyID: "ta", Issuer: taID, Subject: taID, JWKS: taJWKS, Metadata: fetchEndpoint(taID),
	})))
	taMux.HandleFunc("/fetch", serveFetch(imID, sign(intfed.CreateParams{
		Signer: taKey, KeyID: "ta", Issuer: taID, Subject: imID, JWKS: imJWKS, MetadataPolicy: policy(taPolicy),
	})))
	imMux.HandleFunc("/.well-known/openid-federation", serveToken(sign(intfed.CreateParams{
		Signer: imKey, KeyID: "im", Issuer: imID, Subject: imID, JWKS: imJWKS,
		AuthorityHints: []string{taID}, Metadata: fetchEndpoint(imID),
	})))
	imMux.HandleFunc("/fetch", serveFetch(rpID, sign(intfed.CreateParams{
		Signer: imKey, KeyID: "im", Issuer: imID, Subject: rpID, JWKS: rpFedJWKS, MetadataPolicy: policy(imPolicy),
	})))
	rpMux.HandleFunc("/.well-known/openid-federation", serveToken(sign(intfed.CreateParams{
		Signer: rpFedKey, KeyID: "rp-fed", Issuer: rpID, Subject: rpID, JWKS: rpFedJWKS,
		AuthorityHints: []string{imID},
		Metadata:       map[string]json.RawMessage{"openid_relying_party": rpMetadataJSON},
	})))

	return &automaticRegistrationFixture{
		taID: taID, rpID: rpID, taKey: taKey, taJWKS: taJWKS,
		rpOIDCKey: rpOIDCKey, fetcher: network.fetcher(t, servers), now: now,
	}
}

// enableFederatedGrants is an operator enabling client_credentials and
// CIBA for every automatically registered client, and the server-wide
// configuration both need.
func enableFederatedGrants(t *testing.T) func(*server.Config, *server.Dependencies) {
	t.Helper()
	backchannelEndpoint, err := fapi.ParseEndpointURL(testBackchannelAuthenticationEndpoint)
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	return func(cfg *server.Config, deps *server.Dependencies) {
		cfg.ClientCredentialsGrant = true
		cfg.AutomaticRegistration.AllowsClientCredentialsGrant = true
		cfg.AutomaticRegistration.AllowsCIBA = true
		cfg.Endpoints.BackchannelAuthentication = backchannelEndpoint
		cfg.Algorithms.BackchannelAuthenticationRequest = server.AlgorithmSet{fapi.ES256}
		cfg.Limits.BackchannelAuthenticationRequestLifetime = 2 * time.Minute
		cfg.Limits.MaxBackchannelAuthenticationRequestLifetime = time.Minute
		cfg.Limits.BackchannelAuthenticationPollInterval = time.Second
		deps.Backchannel = memstore.NewBackchannelAuthenticationStore()
		deps.BackchannelNotifier = server.NoBackchannelNotifications{}
	}
}

// federatedAssertion is a client assertion f's RP signs for this server.
func federatedAssertion(t *testing.T, f *automaticRegistrationFixture) string {
	t.Helper()
	assertion, err := clientassertion.CreateAssertion(clientassertion.AssertionRequest{
		Signer: f.rpOIDCKey, Algorithm: fapi.ES256, KeyID: "rp-oidc",
		ClientID: f.rpID, Audience: testIssuer, Now: f.now, Lifetime: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("CreateAssertion: %v", err)
	}
	return assertion
}

// federatedClientCredentials is f's RP asking srv for a client_credentials
// token, with authorizationDetails unless it is "".
func federatedClientCredentials(t *testing.T, srv *server.Server, f *automaticRegistrationFixture, authorizationDetails string) error {
	t.Helper()
	params := clientCredentialsFormParams(federatedAssertion(t, f), "accounts")
	if authorizationDetails != "" {
		params = append(params, formParam("authorization_details", authorizationDetails))
	}
	_, err := srv.RequestClientCredentialsToken(context.Background(), server.ClientCredentialsTokenRequest{
		HTTP: server.FormRequest{Parameters: params}, DPoPProofs: []string{createDPoPProof(t, generateKey(t), f.now)},
	})
	return err
}

// federatedBackchannelAuthentication is f's RP sending srv a signed
// backchannel authentication request for user-1, with
// authorizationDetails unless it is "".
func federatedBackchannelAuthentication(t *testing.T, srv *server.Server, f *automaticRegistrationFixture, authorizationDetails string) server.BackchannelAuthenticationAction {
	t.Helper()
	params := standardBackchannelParams(t)
	if authorizationDetails != "" {
		params["authorization_details"] = json.RawMessage(authorizationDetails)
	}
	requestObj, err := requestobject.Create(requestobject.CreateParams{
		Signer: f.rpOIDCKey, Algorithm: fapi.ES256, KeyID: "rp-oidc",
		ClientID: f.rpID, Audience: testIssuer, Now: f.now, Lifetime: 30 * time.Second, Parameters: params,
	})
	if err != nil {
		t.Fatalf("requestobject.Create: %v", err)
	}
	action, err := srv.BeginBackchannelAuthentication(context.Background(), server.BeginBackchannelAuthenticationRequest{
		HTTP: server.FormRequest{Parameters: backchannelFormParams(federatedAssertion(t, f), requestObj)},
	})
	if err != nil {
		t.Fatalf("BeginBackchannelAuthentication: %v", err)
	}
	return action
}

// checkBackchannelRefused fails t unless action refuses the request with
// code.
func checkBackchannelRefused(t *testing.T, action server.BackchannelAuthenticationAction, code server.ErrorCode) {
	t.Helper()
	if refused, ok := action.(server.BackchannelAuthenticationLocalError); !ok || refused.Error.Code() != code {
		t.Errorf("backchannel authentication action = %#v, want a local %s error", action, code)
	}
}

// TestAutomaticRegistrationBranchPolicyWithholdsGrants: a Trust Anchor
// holding a branch of its federation to the authorization code flow,
// with a subset_of on grant_types (the shape OpenID Federation 1.0's own
// examples use), withholds client_credentials and CIBA at the token and
// backchannel authentication endpoints from a Relying Party in that
// branch that leaves grant_types out — though the operator enables both
// for every automatically registered client — and from one whose
// grant_types an Intermediate's value null removes, as it does from one
// publishing grant_types. A policy permitting both grants, or none at
// all, leaves them to a Relying Party listing them (one leaving
// grant_types out never gets them: see
// TestAutomaticRegistrationOmittedGrantTypesMeansCodeFlowOnly).
func TestAutomaticRegistrationBranchPolicyWithholdsGrants(t *testing.T) {
	const cibaGrant = "urn:openid:params:grant-type:ciba"
	grantTypes := func(operators string) string {
		return `{"openid_relying_party":{"grant_types":` + operators + `}}`
	}
	codeFlowOnly := grantTypes(`{"subset_of":["authorization_code","refresh_token"]}`)
	listsAll := map[string]any{"grant_types": []string{"authorization_code", "client_credentials", cibaGrant}}
	for _, tc := range []struct {
		name               string
		taPolicy, imPolicy string
		extra              map[string]any
		wantGranted        bool
	}{
		{name: "grant_types left out", taPolicy: codeFlowOnly},
		{name: "grant_types removed by the Intermediate's value null", taPolicy: codeFlowOnly, imPolicy: grantTypes(`{"value":null}`),
			extra: map[string]any{"grant_types": []string{"authorization_code"}}},
		{name: "grant_types published", taPolicy: codeFlowOnly, extra: listsAll},
		{name: "a policy permitting both", taPolicy: grantTypes(`{"subset_of":["authorization_code","client_credentials","` + cibaGrant + `"]}`),
			extra: listsAll, wantGranted: true},
		{name: "no policy", extra: listsAll, wantGranted: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := setupBranchFixture(t, tc.taPolicy, tc.imPolicy, tc.extra)
			srv := newAutomaticRegistrationTestServer(t, f, enableFederatedGrants(t))
			checkFederatedGrants(t, srv, f, tc.wantGranted)
		})
	}
}

// checkFederatedGrants fails t unless f's RP gets a client_credentials
// token and a backchannel authentication interaction from srv when
// wantGranted, and unauthorized_client at both endpoints otherwise.
func checkFederatedGrants(t *testing.T, srv *server.Server, f *automaticRegistrationFixture, wantGranted bool) {
	t.Helper()
	err := federatedClientCredentials(t, srv, f, "")
	action := federatedBackchannelAuthentication(t, srv, f, "")
	if wantGranted {
		if err != nil {
			t.Errorf("client_credentials = %v, want a token", err)
		}
		if _, ok := action.(server.BackchannelInteractionRequired); !ok {
			t.Errorf("backchannel authentication action = %#v, want an interaction", action)
		}
		return
	}
	if err == nil {
		t.Errorf("client_credentials issued a token, want %s", server.ErrorUnauthorizedClient)
	} else if code := serverErrorCode(t, err); code != server.ErrorUnauthorizedClient {
		t.Errorf("client_credentials error code = %q, want %q", code, server.ErrorUnauthorizedClient)
	}
	checkBackchannelRefused(t, action, server.ErrorUnauthorizedClient)
}

// TestAutomaticRegistrationBranchPolicyNarrowsRARTypes: a superior's
// metadata policy on authorization_details_types narrows the Rich
// Authorization Request types the operator allows every automatically
// registered client, at the token, pushed authorization request and
// backchannel authentication endpoints alike. A payment request from a
// Relying Party in a branch held to account_information is refused with
// invalid_authorization_details, whether the RP publishes payment among
// its types, leaves the parameter out, or has its list removed by an
// Intermediate's value null — though the operator allows payment and its
// RARPolicy passes whatever the registration allows. A policy permitting
// payment, or none at all, leaves it. The RP lists client_credentials and
// CIBA in grant_types, so its requests at those endpoints reach the type
// check.
func TestAutomaticRegistrationBranchPolicyNarrowsRARTypes(t *testing.T) {
	rarTypes := func(operators string) string {
		return `{"openid_relying_party":{"authorization_details_types":` + operators + `}}`
	}
	accountsOnly := rarTypes(`{"subset_of":["account_information"]}`)
	publishesPayment := map[string]any{"authorization_details_types": []string{"payment"}}
	for _, tc := range []struct {
		name               string
		taPolicy, imPolicy string
		extra              map[string]any
		wantAllowed        bool
	}{
		{name: "value", taPolicy: rarTypes(`{"value":["account_information"]}`), extra: publishesPayment},
		{name: "subset_of", taPolicy: accountsOnly, extra: publishesPayment},
		{name: "subset_of, the parameter left out", taPolicy: accountsOnly},
		{name: "subset_of, the RP's types removed by the Intermediate's value null", taPolicy: accountsOnly,
			imPolicy: rarTypes(`{"value":null}`), extra: publishesPayment},
		{name: "a policy permitting payment", taPolicy: rarTypes(`{"subset_of":["payment","account_information"]}`),
			extra: publishesPayment, wantAllowed: true},
		{name: "no policy", wantAllowed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			extra := map[string]any{"grant_types": []string{"authorization_code", "client_credentials", server.CIBAGrantType}}
			maps.Copy(extra, tc.extra)
			f := setupBranchFixture(t, tc.taPolicy, tc.imPolicy, extra)
			srv := newAutomaticRegistrationTestServer(t, f, enableFederatedGrants(t), func(cfg *server.Config, deps *server.Dependencies) {
				cfg.RAR = newTestRARRegistry(t)
				cfg.AutomaticRegistration.AuthorizationDetailsTypes = []string{"payment"}
				deps.ClientCredentialsRARPolicy = server.AllowRequestedAuthorizationDetails{}
				deps.AuthorizationCodeRARPolicy = server.AllowRequestedAuthorizationDetails{}
				deps.CIBARARPolicy = server.AllowRequestedAuthorizationDetails{}
			})

			tokenErr := federatedClientCredentials(t, srv, f, paymentDetails)
			_, parErr := srv.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
				HTTP: server.FormRequest{Parameters: plainFormParameters(t, federatedAssertion(t, f), map[string]string{"authorization_details": paymentDetails})},
			})
			action := federatedBackchannelAuthentication(t, srv, f, paymentDetails)
			if tc.wantAllowed {
				checkPaymentDetailsAllowed(t, tokenErr, parErr, action)
				return
			}
			checkPaymentDetailsRefused(t, tokenErr, parErr, action)
		})
	}
}

// checkPaymentDetailsAllowed fails t unless the client_credentials token
// request (tokenErr), the pushed authorization request (parErr) and the
// backchannel authentication request (action) all accepted the payment
// details.
func checkPaymentDetailsAllowed(t *testing.T, tokenErr, parErr error, action server.BackchannelAuthenticationAction) {
	t.Helper()
	if tokenErr != nil || parErr != nil {
		t.Errorf("client_credentials = %v, PAR = %v; want the payment details accepted", tokenErr, parErr)
	}
	if _, ok := action.(server.BackchannelInteractionRequired); !ok {
		t.Errorf("backchannel authentication action = %#v, want an interaction", action)
	}
}

// checkPaymentDetailsRefused fails t unless the client_credentials token
// request (tokenErr), the pushed authorization request (parErr) and the
// backchannel authentication request (action) all refused the payment
// details with invalid_authorization_details.
func checkPaymentDetailsRefused(t *testing.T, tokenErr, parErr error, action server.BackchannelAuthenticationAction) {
	t.Helper()
	for endpoint, err := range map[string]error{"client_credentials": tokenErr, "PAR": parErr} {
		if code := serverErrorCode(t, err); code != server.ErrorInvalidAuthorizationDetails {
			t.Errorf("%s error code = %q, want %q", endpoint, code, server.ErrorInvalidAuthorizationDetails)
		}
	}
	checkBackchannelRefused(t, action, server.ErrorInvalidAuthorizationDetails)
}

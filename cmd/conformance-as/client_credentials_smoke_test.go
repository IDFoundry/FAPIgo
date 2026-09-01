package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/internal/dpop"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/keys/ephemeral"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// clientCredentialsSmokeServer bundles what both client_credentials smoke
// tests below share: a live HTTP/TLS listener running the exact
// newServerMux wiring main.go uses, with -client-credentials-grant on,
// and the raw crypto.Signer key material needed to build a client
// assertion and DPoP proofs directly — this grant has no PAR/authorize/
// consent step at all, so there's nothing client.Client-shaped worth
// driving through, unlike TestSmokeAuthorizationCodeFlow/TestSmokeMTLSFlow.
type clientCredentialsSmokeServer struct {
	httpClient      *http.Client
	endpoints       server.Endpoints
	accountsURL     fapi.URL
	clientAuthPriv  *ecdsa.PrivateKey
	dpopPriv        *ecdsa.PrivateKey
	clientAuthKeyID string
	clientID        fapi.ClientID
}

func newClientCredentialsSmokeServer(t *testing.T) clientCredentialsSmokeServer {
	t.Helper()
	cert, pool := selfSignedCert(t)
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	tlsListener := tls.NewListener(tcpListener, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})

	issuer, err := fapi.ParseIssuerURL(fmt.Sprintf("https://%s", tcpListener.Addr().String()))
	if err != nil {
		t.Fatalf("parse issuer: %v", err)
	}
	endpoints, err := buildEndpoints(issuer, false)
	if err != nil {
		t.Fatalf("build endpoints: %v", err)
	}
	accountsURL, err := buildAccountsURL(issuer, false)
	if err != nil {
		t.Fatalf("build accounts url: %v", err)
	}

	// This test drives /token and /accounts directly rather than through
	// client.Client (there's no PAR/authorize/consent step to make that
	// worthwhile for this grant), so it needs a real crypto.Signer for
	// both the client assertion and the DPoP proofs, not an
	// ephemeral.KeyManager (whose Sign method is only reachable through
	// client.Client's own signing calls).
	clientAuthPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate client auth key: %v", err)
	}
	const clientAuthKeyID = "client-auth"
	jwk, err := jose.NewJWK(clientAuthPriv.Public(), fapi.ES256)
	if err != nil {
		t.Fatalf("build client jwk: %v", err)
	}
	jwkJSON, err := jwk.WithKeyID(clientAuthKeyID).MarshalJSON()
	if err != nil {
		t.Fatalf("marshal client jwk: %v", err)
	}
	inlineJWKS := json.RawMessage(fmt.Sprintf(`{"keys":[%s]}`, jwkJSON))
	dpopPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate dpop key: %v", err)
	}

	const testClientID = fapi.ClientID("smoke-test-client-credentials-client")
	const testRedirectURI = "https://rp.smoketest.internal/callback"

	registered, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID: testClientID,
		// This grant never redirects anywhere — RedirectURIs is a
		// structural requirement of NewRegisteredClient regardless of
		// which grant types a client actually uses, not something this
		// flow reads.
		RedirectURIs:                 []fapi.RegisteredRedirectURI{testRedirectURI},
		ClientAssertionAlgorithm:     fapi.ES256,
		AllowedScopes:                []string{"accounts"},
		SenderConstrain:              storage.SenderConstrainDPoP,
		AllowsClientCredentialsGrant: true,
	})
	if err != nil {
		t.Fatalf("build registered client: %v", err)
	}

	resolved := ResolvedConfig{
		ListenAddr:        tcpListener.Addr().String(),
		Issuer:            issuer,
		Profile:           server.ProfileFAPISecurity,
		DefaultSubject:    smokeSubject,
		Algorithms:        server.RecommendedAlgorithms(),
		Limits:            server.RecommendedLimits(),
		AccessTokenFormat: AccessTokenFormatJWT,
		Clients:           []storage.RegisteredClient{registered},
		ClientKeys:        []ephemeral.ClientKeySpec{{ClientID: testClientID, JWKS: inlineJWKS}},
		AdvertisedScopes:  []string{"openid", "accounts"},
	}

	mux, err := newServerMux(resolved, false, false, false, false, true, "")
	if err != nil {
		t.Fatalf("build server mux: %v", err)
	}
	httpServer := &http.Server{Handler: mux}
	go httpServer.Serve(tlsListener)
	t.Cleanup(func() { httpServer.Close() })

	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	return clientCredentialsSmokeServer{
		httpClient: httpClient, endpoints: endpoints, accountsURL: accountsURL,
		clientAuthPriv: clientAuthPriv, dpopPriv: dpopPriv, clientAuthKeyID: clientAuthKeyID,
		clientID: testClientID,
	}
}

// TestSmokeClientCredentialsGrantFlow drives the RFC 6749 §4.4
// client_credentials grant end to end over real HTTP: /token, then
// /accounts with the issued access token. This is also the only
// Go-level exercise of accountsHandler/buildAccountsURL (resource.go) —
// every other check of those is live-suite-only (see
// conformance/README.md#client-credentials-grant).
func TestSmokeClientCredentialsGrantFlow(t *testing.T) {
	s := newClientCredentialsSmokeServer(t)

	now := time.Now()
	assertion, err := clientassertion.CreateAssertion(clientassertion.AssertionRequest{
		Signer:    s.clientAuthPriv,
		Algorithm: fapi.ES256,
		KeyID:     s.clientAuthKeyID,
		ClientID:  string(s.clientID),
		Audience:  s.endpoints.Token.String(),
		Now:       now,
		Lifetime:  time.Minute,
	})
	if err != nil {
		t.Fatalf("create client assertion: %v", err)
	}
	tokenURL, err := url.Parse(s.endpoints.Token.String())
	if err != nil {
		t.Fatalf("parse token url: %v", err)
	}
	tokenProof, err := dpop.CreateProof(dpop.ProofRequest{
		Signer:    s.dpopPriv,
		Algorithm: fapi.ES256,
		Method:    http.MethodPost,
		URL:       tokenURL,
		Now:       now,
	})
	if err != nil {
		t.Fatalf("create dpop proof: %v", err)
	}

	form := url.Values{
		"grant_type":            {"client_credentials"},
		"scope":                 {"accounts"},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion},
	}
	req, err := http.NewRequest(http.MethodPost, s.endpoints.Token.String(), strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", tokenProof)
	res, err := s.httpClient.Do(req)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("POST /token: status = %d, want %d", res.StatusCode, http.StatusOK)
	}
	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Scope       string `json:"scope"`
	}
	if err := json.NewDecoder(res.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if tokenResp.TokenType != "DPoP" {
		t.Errorf("token_type = %q, want %q", tokenResp.TokenType, "DPoP")
	}
	if tokenResp.Scope != "accounts" {
		t.Errorf("scope = %q, want %q", tokenResp.Scope, "accounts")
	}
	if tokenResp.AccessToken == "" {
		t.Fatalf("access_token is empty")
	}

	accountsURLValue := s.accountsURL.URL()
	resourceProof, err := dpop.CreateProof(dpop.ProofRequest{
		Signer:      s.dpopPriv,
		Algorithm:   fapi.ES256,
		Method:      http.MethodGet,
		URL:         &accountsURLValue,
		AccessToken: tokenResp.AccessToken,
		Now:         time.Now(),
	})
	if err != nil {
		t.Fatalf("create resource dpop proof: %v", err)
	}
	acctReq, err := http.NewRequest(http.MethodGet, s.accountsURL.String(), nil)
	if err != nil {
		t.Fatalf("build accounts request: %v", err)
	}
	acctReq.Header.Set("Authorization", "DPoP "+tokenResp.AccessToken)
	acctReq.Header.Set("DPoP", resourceProof)
	acctRes, err := s.httpClient.Do(acctReq)
	if err != nil {
		t.Fatalf("GET /accounts: %v", err)
	}
	defer acctRes.Body.Close()
	if acctRes.StatusCode != http.StatusOK {
		t.Fatalf("GET /accounts: status = %d, want %d", acctRes.StatusCode, http.StatusOK)
	}
	var acctBody map[string]any
	if err := json.NewDecoder(acctRes.Body).Decode(&acctBody); err != nil {
		t.Fatalf("decode accounts response: %v", err)
	}
	if _, ok := acctBody["accounts"]; !ok {
		t.Errorf("accounts response = %v, want an \"accounts\" key", acctBody)
	}

	// A bearer token with no client certificate presented to /accounts
	// without the matching DPoP proof must be rejected — proves this
	// endpoint's own binding check runs, not just that the happy path
	// works.
	noProofReq, err := http.NewRequest(http.MethodGet, s.accountsURL.String(), nil)
	if err != nil {
		t.Fatalf("build unbound accounts request: %v", err)
	}
	noProofReq.Header.Set("Authorization", "DPoP "+tokenResp.AccessToken)
	noProofRes, err := s.httpClient.Do(noProofReq)
	if err != nil {
		t.Fatalf("GET /accounts without dpop proof: %v", err)
	}
	defer noProofRes.Body.Close()
	if noProofRes.StatusCode != http.StatusBadRequest {
		t.Errorf("GET /accounts without dpop proof: status = %d, want %d", noProofRes.StatusCode, http.StatusBadRequest)
	}
}

// TestSmokeClientCredentialsGrantFlowWithAuthorizationDetails covers RFC
// 9396 §6's client_credentials support (server/client_credentials.go)
// through this binary's own always-on newSampleRARRegistry wiring
// (wiring.go/rar.go) — the same "prove both sides actually interoperate
// over real HTTP" shape TestSmokeAuthorizationCodeFlowWithAuthorizationDetails
// and TestSmokeCIBAFlowWithAuthorizationDetails already use for the
// PAR/CIBA-shaped flows.
func TestSmokeClientCredentialsGrantFlowWithAuthorizationDetails(t *testing.T) {
	s := newClientCredentialsSmokeServer(t)

	detail, err := extension.RARSet(sampleRARDefinition, sampleTransactionApprovalDetail{Actions: []string{"approve"}, Amount: "SGD 500.00"})
	if err != nil {
		t.Fatalf("RARSet: %v", err)
	}
	authorizationDetailsJSON, err := json.Marshal([]json.RawMessage{detail})
	if err != nil {
		t.Fatalf("marshal authorization_details: %v", err)
	}

	now := time.Now()
	assertion, err := clientassertion.CreateAssertion(clientassertion.AssertionRequest{
		Signer:    s.clientAuthPriv,
		Algorithm: fapi.ES256,
		KeyID:     s.clientAuthKeyID,
		ClientID:  string(s.clientID),
		Audience:  s.endpoints.Token.String(),
		Now:       now,
		Lifetime:  time.Minute,
	})
	if err != nil {
		t.Fatalf("create client assertion: %v", err)
	}
	tokenURL, err := url.Parse(s.endpoints.Token.String())
	if err != nil {
		t.Fatalf("parse token url: %v", err)
	}
	tokenProof, err := dpop.CreateProof(dpop.ProofRequest{
		Signer:    s.dpopPriv,
		Algorithm: fapi.ES256,
		Method:    http.MethodPost,
		URL:       tokenURL,
		Now:       now,
	})
	if err != nil {
		t.Fatalf("create dpop proof: %v", err)
	}

	form := url.Values{
		"grant_type":            {"client_credentials"},
		"scope":                 {"accounts"},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion},
		"authorization_details": {string(authorizationDetailsJSON)},
	}
	req, err := http.NewRequest(http.MethodPost, s.endpoints.Token.String(), strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", tokenProof)
	res, err := s.httpClient.Do(req)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("POST /token: status = %d, want %d", res.StatusCode, http.StatusOK)
	}
	var tokenResp struct {
		AccessToken          string          `json:"access_token"`
		AuthorizationDetails json.RawMessage `json:"authorization_details"`
	}
	if err := json.NewDecoder(res.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if len(tokenResp.AuthorizationDetails) == 0 {
		t.Fatalf("token response is missing authorization_details, want the granted transaction_approval echoed back")
	}
	var got []sampleTransactionApprovalDetail
	if err := json.Unmarshal(tokenResp.AuthorizationDetails, &got); err != nil {
		t.Fatalf("unmarshal authorization_details: %v", err)
	}
	if len(got) != 1 || got[0].Amount != "SGD 500.00" {
		t.Fatalf("authorization_details = %s, want one SGD 500.00 transaction_approval", tokenResp.AuthorizationDetails)
	}
}

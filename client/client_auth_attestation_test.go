package client_test

import (
	"context"
	"crypto"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/internal/clientattestation"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/storage"
)

// testAttestationJWT stands in for the opaque, pre-issued Client
// Attestation JWT fakeAttestationSource hands back — this package
// never inspects its content (see client.AttestationSource's own doc
// comment), so a fixed opaque string is enough to assert it's
// forwarded verbatim as the OAuth-Client-Attestation header value.
const testAttestationJWT = "opaque-client-attestation-jwt"

// fakeAttestationSource is a minimal client.AttestationSource that
// always returns the same held Client Attestation JWT (or, if err is
// set, always fails) — this package never refreshes or inspects the
// held value itself, so a fixed value is sufficient to exercise every
// call site that resolves one.
type fakeAttestationSource struct {
	attestation string
	err         error
}

func (f fakeAttestationSource) CurrentAttestation(context.Context) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return f.attestation, nil
}

// mustConfirmationJWK builds the raw JWK bytes internal/clientattestation's
// own PoP.Verify expects as its confirmation key — the same shape
// server/client_auth_attestation.go extracts from an Attestation's own
// "cnf.jwk" claim. These tests never build a full Attestation JWT of
// their own (see fakeAttestationSource's own doc comment), so pub is
// supplied directly from the fake key manager's own public half
// instead.
func mustConfirmationJWK(t *testing.T, pub crypto.PublicKey) []byte {
	t.Helper()
	jwk, err := jose.NewJWK(pub, fapi.ES256)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}
	raw, err := jwk.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	return raw
}

// fakeAttestationAuthAS is a minimal fixture for a client
// authenticating via ClientAuthMethodAttestation: it captures both the
// request form (to assert no client_id/client_assertion* field is
// present — see addClientAuthentication's own doc comment) and the two
// Attestation-Based Client Authentication headers (to assert they
// carry a verifiable PoP), across PAR, token, client-credentials and
// CIBA backchannel-authentication requests.
type fakeAttestationAuthAS struct {
	t               *testing.T
	confirmationJWK []byte

	lastPARForm, lastTokenForm, lastBCForm          url.Values
	lastPARHeaders, lastTokenHeaders, lastBCHeaders http.Header
}

func (a *fakeAttestationAuthAS) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/par", a.handlePAR)
	mux.HandleFunc("/token", a.handleToken)
	mux.HandleFunc("/backchannel-authenticate", a.handleBackchannel)
	return mux
}

// checkAttestationAuthShape asserts form carries no client_assertion*
// (never sent under Attestation-Based Client Authentication — see
// addClientAuthentication's own doc comment) and that headers carry a
// well-formed, cryptographically verifiable Attestation-Based Client
// Authentication pair — the held Attestation JWT verbatim, plus a PoP
// whose signature, issuer (client_id) and audience (this AS's own
// issuer identifier) all check out against confirmationJWK. It
// deliberately does not check for an absent client_id: PAR's own form
// always carries one as a normal RFC 6749 §4.1.1 authorization
// parameter (see BeginAuthorization's own params map), independent of
// how the client authenticates — the PAR-specific test below checks
// that field for its own, different reason.
func (a *fakeAttestationAuthAS) checkAttestationAuthShape(t *testing.T, form url.Values, headers http.Header, label string) {
	t.Helper()
	if form.Get("client_assertion") != "" {
		t.Errorf("%s: unexpected client_assertion form field under Attestation-Based Client Authentication", label)
	}
	if form.Get("client_assertion_type") != "" {
		t.Errorf("%s: unexpected client_assertion_type form field under Attestation-Based Client Authentication", label)
	}
	if got := headers.Get("OAuth-Client-Attestation"); got != testAttestationJWT {
		t.Errorf("%s: OAuth-Client-Attestation header = %q, want %q", label, got, testAttestationJWT)
	}
	popCompact := headers.Get("OAuth-Client-Attestation-PoP")
	if popCompact == "" {
		t.Fatalf("%s: OAuth-Client-Attestation-PoP header missing", label)
	}
	pop, err := clientattestation.ParsePoP(popCompact)
	if err != nil {
		t.Fatalf("%s: ParsePoP: %v", label, err)
	}
	verified, err := pop.Verify(context.Background(), a.confirmationJWK, clientattestation.PoPVerifyPolicy{
		ExpectedIssuer: testClientID, ExpectedAudience: testIssuer,
		Now: time.Now(), MaxAge: time.Minute,
	})
	if err != nil {
		t.Fatalf("%s: PoP.Verify: %v", label, err)
	}
	if verified.ClientID != testClientID {
		t.Errorf("%s: PoP ClientID = %q, want %q", label, verified.ClientID, testClientID)
	}
}

func (a *fakeAttestationAuthAS) handlePAR(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.t.Fatalf("PAR: parse form: %v", err)
	}
	a.lastPARForm = r.PostForm
	a.lastPARHeaders = r.Header.Clone()
	a.checkAttestationAuthShape(a.t, r.PostForm, r.Header, "PAR")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"request_uri": "urn:ietf:params:oauth:request_uri:abc123",
		"expires_in":  60,
	})
}

func (a *fakeAttestationAuthAS) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.t.Fatalf("token: parse form: %v", err)
	}
	a.lastTokenForm = r.PostForm
	a.lastTokenHeaders = r.Header.Clone()
	a.checkAttestationAuthShape(a.t, r.PostForm, r.Header, "token")

	w.Header().Set("Content-Type", "application/json")
	// SenderConstrain stays the default (DPoP) in every test below, so
	// the expected token_type is "DPoP" — ClientAuthMethod and
	// SenderConstrain are independent concerns, mirroring
	// fakeCertAuthAS's identical reasoning.
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": "opaque-access-token",
		"token_type":   "DPoP",
		"expires_in":   300,
		"scope":        "openid accounts",
	})
}

func (a *fakeAttestationAuthAS) handleBackchannel(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.t.Fatalf("backchannel-authenticate: parse form: %v", err)
	}
	a.lastBCForm = r.PostForm
	a.lastBCHeaders = r.Header.Clone()
	a.checkAttestationAuthShape(a.t, r.PostForm, r.Header, "backchannel-authenticate")

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"auth_req_id": "test-auth-req-id",
		"expires_in":  120,
		"interval":    5,
	})
}

// newTestClientWithAttestationAuth builds a client configured for
// ClientAuthMethodAttestation (browser flow only — authorization + PAR
// + token, plus client_credentials since it shares the token
// endpoint). SenderConstrain stays the default (DPoP).
func newTestClientWithAttestationAuth(t *testing.T) (*client.Client, *fakeAttestationAuthAS) {
	t.Helper()
	km := newFakeKeyManager(t, keys.ClientAttestationPoPSigning, keys.DPoPProofSigning)
	info, err := km.PublicKey(context.Background(), keys.ClientAttestationPoPSigning, fapi.ES256)
	if err != nil {
		t.Fatalf("PublicKey(ClientAttestationPoPSigning): %v", err)
	}

	as := &fakeAttestationAuthAS{t: t, confirmationJWK: mustConfirmationJWK(t, info.PublicKey)}
	ts := httptest.NewServer(as.handler())
	t.Cleanup(ts.Close)

	cfg := validConfig(t)
	cfg.ClientAuthMethod = storage.ClientAuthMethodAttestation
	cfg.Algorithms.ClientAuthentication = 0
	cfg.Limits.ClientAssertionLifetime = 0
	cfg.Algorithms.ClientAttestationPoP = fapi.ES256
	parURL, err := fapi.ParseEndpointURL(ts.URL+"/par", fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseEndpointURL(par): %v", err)
	}
	tokenURL, err := fapi.ParseEndpointURL(ts.URL+"/token", fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseEndpointURL(token): %v", err)
	}
	cfg.Endpoints.PushedAuthorizationRequest = parURL
	cfg.Endpoints.Token = tokenURL

	deps := validDependencies(t)
	deps.HTTP = ts.Client()
	deps.Keys = km
	deps.Attestation = fakeAttestationSource{attestation: testAttestationJWT}

	c, err := client.New(cfg, deps)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	return c, as
}

// TestBeginAuthorizationAttestationSendsHeaders confirms PAR carries
// the two Attestation headers and no client_assertion — client_id
// itself is expected here regardless of ClientAuthMethod (PAR conveys
// the whole authorization request, and client_id is a normal RFC 6749
// §4.1.1 authorization parameter, not specific to authentication).
func TestBeginAuthorizationAttestationSendsHeaders(t *testing.T) {
	c, as := newTestClientWithAttestationAuth(t)
	if _, err := c.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{Scope: []string{"openid", "accounts"}}); err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	if as.lastPARForm.Get("client_id") != testClientID {
		t.Errorf("PAR: client_id = %q, want %q", as.lastPARForm.Get("client_id"), testClientID)
	}
	if as.lastPARHeaders.Get("OAuth-Client-Attestation") == "" {
		t.Errorf("PAR: missing OAuth-Client-Attestation header")
	}
}

func TestExchangeCodeAttestationSendsHeadersNoClientAssertion(t *testing.T) {
	c, as := newTestClientWithAttestationAuth(t)
	ctx := context.Background()

	session, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid", "accounts"}})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	rawQuery := mtlsCallbackFor(testIssuer, session.Handle().String(), "auth-code-123")
	if _, err := c.CompleteAuthorization(ctx, client.AuthorizationCallback{RawQuery: rawQuery}); err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	if as.lastTokenForm.Get("client_assertion") != "" {
		t.Errorf("token: unexpected client_assertion")
	}
	if as.lastTokenHeaders.Get("OAuth-Client-Attestation-PoP") == "" {
		t.Errorf("token: missing OAuth-Client-Attestation-PoP header")
	}
}

func TestRequestClientCredentialsTokenAttestationSendsHeaders(t *testing.T) {
	c, as := newTestClientWithAttestationAuth(t)
	if _, err := c.RequestClientCredentialsToken(context.Background(), client.ClientCredentialsTokenRequest{Scope: []string{"accounts"}}); err != nil {
		t.Fatalf("RequestClientCredentialsToken: %v", err)
	}
	if as.lastTokenForm.Get("client_id") != "" {
		t.Errorf("token: unexpected client_id")
	}
	if as.lastTokenHeaders.Get("OAuth-Client-Attestation") == "" {
		t.Errorf("token: missing OAuth-Client-Attestation header")
	}
}

// TestBeginBackchannelAuthenticationAndPollAttestationSendsHeaders
// mirrors TestBeginBackchannelAuthenticationSelfSignedTLSClientAuthSendsClientIDNoAssertion's
// shape for ClientAuthMethodAttestation: the CIBA backchannel
// authentication request object is still signed unconditionally
// (FAPI-CIBA always requires one), but both it and the later
// token-endpoint poll must carry the two Attestation headers instead
// of any client_id/client_assertion.
func TestBeginBackchannelAuthenticationAndPollAttestationSendsHeaders(t *testing.T) {
	km := newFakeKeyManager(t, keys.ClientAttestationPoPSigning, keys.DPoPProofSigning, keys.BackchannelAuthenticationRequestSigning)
	info, err := km.PublicKey(context.Background(), keys.ClientAttestationPoPSigning, fapi.ES256)
	if err != nil {
		t.Fatalf("PublicKey(ClientAttestationPoPSigning): %v", err)
	}

	as := &fakeAttestationAuthAS{t: t, confirmationJWK: mustConfirmationJWK(t, info.PublicKey)}
	ts := httptest.NewServer(as.handler())
	defer ts.Close()

	cfg := validConfig(t)
	cfg.ClientAuthMethod = storage.ClientAuthMethodAttestation
	cfg.Algorithms.ClientAuthentication = 0
	cfg.Limits.ClientAssertionLifetime = 0
	cfg.Algorithms.ClientAttestationPoP = fapi.ES256
	bcURL, err := fapi.ParseEndpointURL(ts.URL+"/backchannel-authenticate", fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseEndpointURL(backchannel-authenticate): %v", err)
	}
	tokenURL, err := fapi.ParseEndpointURL(ts.URL+"/token", fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseEndpointURL(token): %v", err)
	}
	cfg.Endpoints.Token = tokenURL
	cfg.Endpoints.BackchannelAuthentication = bcURL
	cfg.Algorithms.BackchannelAuthenticationRequest = fapi.ES256
	cfg.Limits.BackchannelAuthenticationRequestLifetime = time.Minute

	deps := validDependencies(t)
	deps.HTTP = ts.Client()
	deps.Keys = km
	deps.Attestation = fakeAttestationSource{attestation: testAttestationJWT}

	c, err := client.New(cfg, deps)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}

	ctx := context.Background()
	session, err := c.BeginBackchannelAuthentication(ctx, client.BeginBackchannelAuthenticationRequest{
		Scope: []string{"openid", "accounts"}, LoginHint: "user@example.com",
	})
	if err != nil {
		t.Fatalf("BeginBackchannelAuthentication: %v", err)
	}
	if as.lastBCForm.Get("client_id") != "" {
		t.Errorf("backchannel-authenticate: unexpected client_id")
	}
	if as.lastBCHeaders.Get("OAuth-Client-Attestation") == "" {
		t.Errorf("backchannel-authenticate: missing OAuth-Client-Attestation header")
	}

	if _, err := c.PollBackchannelAuthentication(ctx, session); err != nil {
		t.Fatalf("PollBackchannelAuthentication: %v", err)
	}
	if as.lastTokenHeaders.Get("OAuth-Client-Attestation-PoP") == "" {
		t.Errorf("poll: missing OAuth-Client-Attestation-PoP header")
	}
}

// TestNewAcceptsClientAuthMethodAttestation confirms a fully configured
// ClientAuthMethodAttestation client (algorithm + Dependencies.Attestation,
// no Algorithms.ClientAuthentication/Limits.ClientAssertionLifetime)
// constructs successfully.
func TestNewAcceptsClientAuthMethodAttestation(t *testing.T) {
	cfg := validConfig(t)
	cfg.ClientAuthMethod = storage.ClientAuthMethodAttestation
	cfg.Algorithms.ClientAuthentication = 0
	cfg.Limits.ClientAssertionLifetime = 0
	cfg.Algorithms.ClientAttestationPoP = fapi.ES256

	deps := validDependencies(t)
	deps.Attestation = fakeAttestationSource{attestation: testAttestationJWT}

	if _, err := client.New(cfg, deps); err != nil {
		t.Fatalf("New(ClientAuthMethodAttestation, fully configured): %v", err)
	}
}

func TestNewRejectsClientAuthMethodAttestationWithoutAlgorithm(t *testing.T) {
	cfg := validConfig(t)
	cfg.ClientAuthMethod = storage.ClientAuthMethodAttestation
	cfg.Algorithms.ClientAuthentication = 0
	cfg.Limits.ClientAssertionLifetime = 0

	deps := validDependencies(t)
	deps.Attestation = fakeAttestationSource{attestation: testAttestationJWT}

	if _, err := client.New(cfg, deps); err == nil {
		t.Fatalf("New(ClientAuthMethodAttestation, no algorithms.client_attestation_pop) = nil error, want error")
	}
}

func TestNewRejectsClientAuthMethodAttestationWithoutAttestationDependency(t *testing.T) {
	cfg := validConfig(t)
	cfg.ClientAuthMethod = storage.ClientAuthMethodAttestation
	cfg.Algorithms.ClientAuthentication = 0
	cfg.Limits.ClientAssertionLifetime = 0
	cfg.Algorithms.ClientAttestationPoP = fapi.ES256

	deps := validDependencies(t)

	if _, err := client.New(cfg, deps); err == nil {
		t.Fatalf("New(ClientAuthMethodAttestation, no Dependencies.Attestation) = nil error, want error")
	}
}

// TestPublicJWKSOmitsAnyKeyUnderAttestationAuth confirms PublicJWKS
// publishes no key at all under ClientAuthMethodAttestation — the
// Client Instance Key is vouched for inline via the held Attestation's
// own "cnf.jwk" claim, never via discovery (see
// PoPCreateRequest.Signer's own doc comment), so there is nothing for
// PublicJWKS to publish here, the same as under any RFC 8705 mTLS
// method (TestPublicJWKSOmitsClientAuthenticationKeyUnderCertBasedAuth).
func TestPublicJWKSOmitsAnyKeyUnderAttestationAuth(t *testing.T) {
	cfg := validConfig(t)
	cfg.ClientAuthMethod = storage.ClientAuthMethodAttestation
	cfg.Algorithms.ClientAuthentication = 0
	cfg.Limits.ClientAssertionLifetime = 0
	cfg.Algorithms.ClientAttestationPoP = fapi.ES256

	deps := validDependencies(t)
	deps.Attestation = fakeAttestationSource{attestation: testAttestationJWT}

	c, err := client.New(cfg, deps)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	set, err := c.PublicJWKS(context.Background())
	if err != nil {
		t.Fatalf("PublicJWKS: %v", err)
	}
	if len(set.Keys) != 0 {
		t.Fatalf("len(Keys) = %d, want 0", len(set.Keys))
	}
}

package client_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/storage"
)

// fakeCertAuthAS is a minimal fixture for a client authenticating via
// ClientAuthMethodSelfSignedTLSClientAuth/ClientAuthMethodTLSClientAuth
// — RFC 8705 §2's "client_id, no client_assertion" shape — deliberately
// separate from fakeMTLSAS (mtls_test.go), which asserts the opposite
// (a present client_assertion): that fixture covers SenderConstrain,
// an orthogonal concern from ClientAuthMethod.
type fakeCertAuthAS struct {
	t *testing.T

	lastPARForm   url.Values
	lastTokenForm url.Values
	lastBCForm    url.Values
}

func (a *fakeCertAuthAS) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/par", a.handlePAR)
	mux.HandleFunc("/token", a.handleToken)
	mux.HandleFunc("/backchannel-authenticate", a.handleBackchannel)
	return mux
}

func (a *fakeCertAuthAS) checkCertAuthShape(t *testing.T, form url.Values, label string) {
	t.Helper()
	if form.Get("client_id") == "" {
		t.Errorf("%s: missing client_id", label)
	}
	if form.Get("client_assertion") != "" {
		t.Errorf("%s: unexpected client_assertion presented by a certificate-authenticated client", label)
	}
	if form.Get("client_assertion_type") != "" {
		t.Errorf("%s: unexpected client_assertion_type presented by a certificate-authenticated client", label)
	}
}

func (a *fakeCertAuthAS) handlePAR(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.t.Fatalf("PAR: parse form: %v", err)
	}
	a.lastPARForm = r.PostForm
	a.checkCertAuthShape(a.t, r.PostForm, "PAR")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"request_uri": "urn:ietf:params:oauth:request_uri:abc123",
		"expires_in":  60,
	})
}

func (a *fakeCertAuthAS) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.t.Fatalf("token: parse form: %v", err)
	}
	a.lastTokenForm = r.PostForm
	a.checkCertAuthShape(a.t, r.PostForm, "token")

	w.Header().Set("Content-Type", "application/json")
	// ClientAuthMethod and SenderConstrain are independent — these test
	// clients leave SenderConstrain at its default (DPoP), so the
	// expected token_type is "DPoP", not "Bearer" (RFC 8705 §3.4's
	// "Bearer" applies only under SenderConstrainMTLS, covered instead
	// by mtls_test.go's fakeMTLSAS).
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": "opaque-access-token",
		"token_type":   "DPoP",
		"expires_in":   300,
		"scope":        "openid accounts",
	})
}

func (a *fakeCertAuthAS) handleBackchannel(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.t.Fatalf("backchannel-authenticate: parse form: %v", err)
	}
	a.lastBCForm = r.PostForm
	a.checkCertAuthShape(a.t, r.PostForm, "backchannel-authenticate")

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"auth_req_id": "test-auth-req-id",
		"expires_in":  120,
		"interval":    5,
	})
}

// newTestClientWithCertAuth builds a client configured for
// authMethod's certificate-based authentication (browser flow only —
// authorization + PAR + token). SenderConstrain stays the default
// (DPoP) — ClientAuthMethod and SenderConstrain are independent
// concerns, so this deliberately doesn't also exercise mTLS
// sender-constraining, unlike newTestClientWithMTLS.
func newTestClientWithCertAuth(t *testing.T, authMethod storage.ClientAuthMethod) (*client.Client, *fakeCertAuthAS) {
	t.Helper()
	as := &fakeCertAuthAS{t: t}
	ts := httptest.NewServer(as.handler())
	t.Cleanup(ts.Close)

	cfg := validConfig(t)
	cfg.ClientAuthMethod = authMethod
	cfg.Algorithms.ClientAuthentication = 0
	cfg.Limits.ClientAssertionLifetime = 0
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

	c, err := client.New(cfg, deps)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	return c, as
}

func TestBeginAuthorizationSelfSignedTLSClientAuthSendsClientIDNoAssertion(t *testing.T) {
	c, as := newTestClientWithCertAuth(t, storage.ClientAuthMethodSelfSignedTLSClientAuth)
	if _, err := c.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{Scope: []string{"openid", "accounts"}}); err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	if as.lastPARForm.Get("client_id") == "" {
		t.Errorf("PAR client_id missing")
	}
}

func TestExchangeCodeTLSClientAuthSendsClientIDNoAssertion(t *testing.T) {
	c, as := newTestClientWithCertAuth(t, storage.ClientAuthMethodTLSClientAuth)
	ctx := context.Background()

	session, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid", "accounts"}})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	rawQuery := mtlsCallbackFor(testIssuer, session.Handle().String(), "auth-code-123")
	if _, err := c.CompleteAuthorization(ctx, client.AuthorizationCallback{RawQuery: rawQuery}); err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	if as.lastTokenForm.Get("client_id") == "" {
		t.Errorf("token client_id missing")
	}
	if as.lastTokenForm.Get("client_assertion") != "" {
		t.Errorf("token client_assertion present, want none")
	}
}

// TestBeginBackchannelAuthenticationSelfSignedTLSClientAuthSendsClientIDNoAssertion
// mirrors TestBeginBackchannelAuthenticationAndPollMTLSSendNoDPoPHeader's
// shape for ClientAuthMethod instead of SenderConstrain — CIBA's
// backchannel authentication request object is still signed
// unconditionally (FAPI-CIBA always requires one, independent of how the
// client authenticates), but the surrounding form must carry client_id,
// not client_assertion.
func TestBeginBackchannelAuthenticationSelfSignedTLSClientAuthSendsClientIDNoAssertion(t *testing.T) {
	as := &fakeCertAuthAS{t: t}
	ts := httptest.NewServer(as.handler())
	defer ts.Close()

	cfg := validConfig(t)
	cfg.ClientAuthMethod = storage.ClientAuthMethodSelfSignedTLSClientAuth
	cfg.Algorithms.ClientAuthentication = 0
	cfg.Limits.ClientAssertionLifetime = 0
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
	deps.Keys = newFakeKeyManager(t, keys.BackchannelAuthenticationRequestSigning, keys.DPoPProofSigning)

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
	if as.lastBCForm.Get("client_id") == "" {
		t.Errorf("backchannel-authenticate client_id missing")
	}

	if _, err := c.PollBackchannelAuthentication(ctx, session); err != nil {
		t.Fatalf("PollBackchannelAuthentication: %v", err)
	}
	// PollBackchannelAuthentication posts to the same /token endpoint,
	// overwriting lastTokenForm — check it again for the poll request's
	// own shape.
	as.checkCertAuthShape(t, as.lastTokenForm, "poll")
}

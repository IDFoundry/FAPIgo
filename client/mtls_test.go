package client_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/internal/token"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/storage"
)

// fakeMTLSAS is fakeAS's mTLS-sender-constrained counterpart — a
// deliberately separate, minimal fixture rather than adding
// SenderConstrain-conditional branches throughout fakeAS itself, which
// every other flow_test.go test also relies on. It asserts no DPoP
// header is ever presented (the whole point of SenderConstrainMTLS)
// and returns "token_type": "Bearer" (RFC 8705 §3.4) unless
// tokenTypeOverride says otherwise.
type fakeMTLSAS struct {
	t          *testing.T
	idTokenKey *ecdsa.PrivateKey
	issuer     string

	// tokenTypeOverride, if non-empty, replaces the token response's
	// token_type value — for testing that an mTLS-bound client rejects
	// an unexpected one.
	tokenTypeOverride string

	lastPARForm   url.Values
	lastTokenForm url.Values
	lastNonce     string
}

func newFakeMTLSAS(t *testing.T, issuer string) *fakeMTLSAS {
	t.Helper()
	idKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate id token key: %v", err)
	}
	return &fakeMTLSAS{t: t, idTokenKey: idKey, issuer: issuer}
}

func (a *fakeMTLSAS) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/par", a.handlePAR)
	mux.HandleFunc("/token", a.handleToken)
	return mux
}

func (a *fakeMTLSAS) handlePAR(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.t.Fatalf("PAR: parse form: %v", err)
	}
	a.lastPARForm = r.PostForm
	if r.Header.Get("DPoP") != "" {
		a.t.Errorf("PAR: unexpected DPoP header presented by an mTLS-bound client")
	}
	if r.PostForm.Get("client_assertion") == "" {
		a.t.Errorf("PAR: missing client_assertion")
	}
	if r.PostForm.Get("code_challenge") == "" {
		a.t.Errorf("PAR: missing code_challenge")
	}
	a.lastNonce = r.PostForm.Get("nonce")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{
		"request_uri": "urn:ietf:params:oauth:request_uri:abc123",
		"expires_in":  60,
	})
}

func (a *fakeMTLSAS) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.t.Fatalf("token: parse form: %v", err)
	}
	a.lastTokenForm = r.PostForm
	if r.Header.Get("DPoP") != "" {
		a.t.Errorf("token: unexpected DPoP header presented by an mTLS-bound client")
	}
	if r.PostForm.Get("client_assertion") == "" {
		a.t.Errorf("token: missing client_assertion")
	}

	idToken, err := token.IssueIDToken(token.IDTokenParams{
		Signer: a.idTokenKey, Algorithm: fapi.ES256, KeyID: "as-id-kid",
		Issuer: a.issuer, Subject: "end-user-1", Audience: testClientID,
		Nonce: a.lastNonce, Now: time.Now(), Lifetime: time.Minute,
	})
	if err != nil {
		a.t.Fatalf("issue id token: %v", err)
	}

	tokenType := "Bearer"
	if a.tokenTypeOverride != "" {
		tokenType = a.tokenTypeOverride
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"access_token":  "opaque-access-token",
		"token_type":    tokenType,
		"expires_in":    300,
		"scope":         "openid accounts",
		"id_token":      idToken,
		"refresh_token": "opaque-refresh-token",
	})
}

func newTestClientWithMTLS(t *testing.T) (*client.Client, *fakeMTLSAS, *httptest.Server) {
	t.Helper()
	as := newFakeMTLSAS(t, testIssuer)
	ts := httptest.NewServer(as.handler())
	t.Cleanup(ts.Close)

	cfg := validConfig(t)
	cfg.SenderConstrain = storage.SenderConstrainMTLS
	cfg.Algorithms.DPoP = 0
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
	deps.IssuerKeys = &fakeIssuerKeySource{keys: map[keys.IssuerVerificationPurpose]crypto.PublicKey{
		keys.IDTokenVerification: &as.idTokenKey.PublicKey,
	}}

	c, err := client.New(cfg, deps)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	return c, as, ts
}

func TestBeginAuthorizationMTLSSendsNoDPoPHeader(t *testing.T) {
	c, as, _ := newTestClientWithMTLS(t)
	if _, err := c.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{Scope: []string{"openid", "accounts"}}); err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	if as.lastPARForm.Get("client_assertion") == "" {
		t.Errorf("PAR client_assertion missing")
	}
}

// callbackFor builds the query string a real authorization server would
// redirect back with for session, mirroring fakeAS.callbackFor's own
// plain-mode shape (mTLS sender-constraining is orthogonal to the
// response mode, so the baseline profile's plain query-param callback
// applies unchanged).
func mtlsCallbackFor(issuer, state, code string) string {
	return "code=" + code + "&state=" + state + "&iss=" + issuer
}

func TestExchangeCodeMTLSBindingHappyPath(t *testing.T) {
	c, as, _ := newTestClientWithMTLS(t)
	ctx := context.Background()

	session, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid", "accounts"}})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}

	rawQuery := mtlsCallbackFor(testIssuer, session.Handle().String(), "auth-code-123")
	result, err := c.CompleteAuthorization(ctx, client.AuthorizationCallback{RawQuery: rawQuery})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	success, ok := result.(client.CompletionSuccess)
	if !ok {
		t.Fatalf("result type = %T, want client.CompletionSuccess", result)
	}
	if success.Tokens.TokenType != "Bearer" {
		t.Errorf("TokenType = %q, want %q", success.Tokens.TokenType, "Bearer")
	}
	if success.Tokens.AccessToken.Reveal() != "opaque-access-token" {
		t.Errorf("AccessToken = %q", success.Tokens.AccessToken.Reveal())
	}
	if !success.Tokens.HasIDToken {
		t.Errorf("HasIDToken = false, want true")
	}
	if as.lastTokenForm.Get("client_assertion") == "" {
		t.Errorf("token client_assertion missing")
	}
}

// TestBeginBackchannelAuthenticationAndPollMTLSSendNoDPoPHeader is a
// compact, purpose-built check that CIBA's own two entry points
// (BeginBackchannelAuthentication, PollBackchannelAuthentication) skip
// DPoP proof building under SenderConstrainMTLS too, the same way the
// browser flow's PAR/token calls do above — a separate minimal fixture
// rather than adding SenderConstrain-conditional branches to
// fakeCIBAAS (backchannel_test.go), which 11 other tests share.
func TestBeginBackchannelAuthenticationAndPollMTLSSendNoDPoPHeader(t *testing.T) {
	var sawBCDPoPHeader, sawPollDPoPHeader bool
	mux := http.NewServeMux()
	mux.HandleFunc("/backchannel-authenticate", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("DPoP") != "" {
			sawBCDPoPHeader = true
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"auth_req_id": "test-auth-req-id",
			"expires_in":  120,
			"interval":    5,
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("DPoP") != "" {
			sawPollDPoPHeader = true
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "opaque-access-token",
			"token_type":   "Bearer",
			"expires_in":   300,
			"scope":        "openid accounts",
		})
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	cfg := validConfig(t)
	cfg.SenderConstrain = storage.SenderConstrainMTLS
	cfg.Algorithms.DPoP = 0
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
	deps.Keys = newFakeKeyManager(t, keys.ClientAuthentication, keys.BackchannelAuthenticationRequestSigning)

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
	if sawBCDPoPHeader {
		t.Errorf("backchannel-authenticate: unexpected DPoP header presented by an mTLS-bound client")
	}

	result, err := c.PollBackchannelAuthentication(ctx, session)
	if err != nil {
		t.Fatalf("PollBackchannelAuthentication: %v", err)
	}
	if sawPollDPoPHeader {
		t.Errorf("token: unexpected DPoP header presented by an mTLS-bound client")
	}
	approved, ok := result.(client.BackchannelAuthenticationApproved)
	if !ok {
		t.Fatalf("result type = %T, want client.BackchannelAuthenticationApproved", result)
	}
	if approved.Tokens.TokenType != "Bearer" {
		t.Errorf("TokenType = %q, want %q", approved.Tokens.TokenType, "Bearer")
	}
}

// TestProtectedResourceDoMTLSSendsBearerNoDPoPProof mirrors
// TestProtectedResourceDoAttachesAuthorizationAndDPoPProof
// (resource_test.go) for SenderConstrainMTLS: "Authorization: Bearer
// <token>" and no DPoP header at all.
func TestProtectedResourceDoMTLSSendsBearerNoDPoPProof(t *testing.T) {
	const accessToken = "test-access-token"
	var gotAuth, gotProof string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotProof = r.Header.Get("DPoP")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()

	c := newResourceTestClient(t, ts, func(cfg *client.Config) {
		cfg.SenderConstrain = storage.SenderConstrainMTLS
		cfg.Algorithms.DPoP = 0
	})
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/resource", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}

	res, err := c.ProtectedResource(client.TokenSet{AccessToken: fapi.NewSecret(accessToken)}).Do(context.Background(), req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer res.Body.Close()

	if gotAuth != "Bearer "+accessToken {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer "+accessToken)
	}
	if gotProof != "" {
		t.Errorf("DPoP header = %q, want empty for an mTLS-bound request", gotProof)
	}
}

func TestExchangeCodeMTLSRejectsUnexpectedTokenType(t *testing.T) {
	c, as, _ := newTestClientWithMTLS(t)
	as.tokenTypeOverride = "DPoP"
	ctx := context.Background()

	session, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid", "accounts"}})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	rawQuery := mtlsCallbackFor(testIssuer, session.Handle().String(), "auth-code-123")

	if _, err := c.CompleteAuthorization(ctx, client.AuthorizationCallback{RawQuery: rawQuery}); err == nil {
		t.Fatalf("CompleteAuthorization(unexpected token_type) = nil error, want error")
	}
}

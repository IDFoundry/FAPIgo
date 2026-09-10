package client_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/storage"
)

// TestRequestClientCredentialsTokenRejectsEmptyScope confirms an empty
// scope is rejected locally, before any network call — the server
// (server.RequestClientCredentialsToken) always requires at least one,
// so this would otherwise fail only after a wasted round trip.
func TestRequestClientCredentialsTokenRejectsEmptyScope(t *testing.T) {
	c, err := client.New(validConfig(t), validDependencies(t))
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	_, err = c.RequestClientCredentialsToken(context.Background(), client.ClientCredentialsTokenRequest{})
	if err == nil {
		t.Fatalf("RequestClientCredentialsToken(empty scope) = nil error, want error")
	}
	var cerr *client.Error
	if !errors.As(err, &cerr) {
		t.Fatalf("error is not *client.Error: %v", err)
	}
	if cerr.Code() != client.ErrorInvalidRequest {
		t.Errorf("Code() = %q, want %q", cerr.Code(), client.ErrorInvalidRequest)
	}
}

// fakeClientCredentialsAS is a deliberately minimal, purpose-built fake
// token endpoint for RequestClientCredentialsToken — mirroring
// fakeMTLSAS's own precedent (mtls_test.go) of a dedicated fixture
// rather than adding client_credentials-only branches to fakeAS, which
// every browser-flow test in this package also relies on. It echoes
// back the request's own scope and authorization_details, and can be
// made to fail in the ways a real token endpoint fails.
type fakeClientCredentialsAS struct {
	t *testing.T

	lastForm url.Values

	rejectPlain       bool
	malformedResponse bool
	tokenTypeOverride string
	omitExpiresIn     bool
}

func (a *fakeClientCredentialsAS) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/token", a.handleToken)
	return mux
}

func (a *fakeClientCredentialsAS) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.t.Fatalf("token: parse form: %v", err)
	}
	a.lastForm = r.PostForm

	if a.rejectPlain {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{
			"error":             "invalid_scope",
			"error_description": "test: rejected",
		})
		return
	}
	if a.malformedResponse {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"token_type":"DPoP"`)) // deliberately truncated JSON, no access_token
		return
	}

	tokenType := "DPoP"
	if r.Header.Get("DPoP") == "" {
		tokenType = "Bearer"
	}
	if a.tokenTypeOverride != "" {
		tokenType = a.tokenTypeOverride
	}
	resp := map[string]any{
		"access_token": "opaque-client-credentials-token",
		"token_type":   tokenType,
		"scope":        r.PostForm.Get("scope"),
	}
	if !a.omitExpiresIn {
		resp["expires_in"] = 300
	}
	if raw := r.PostForm.Get("authorization_details"); raw != "" {
		resp["authorization_details"] = json.RawMessage(raw)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// newTestClientForClientCredentials builds a *client.Client pointed at a
// fresh fakeClientCredentialsAS — cfg lets a test override SenderConstrain/
// ClientAuthMethod before New is called, the same pattern
// newTestClientWithMTLS's own caller-supplied cfg mutation follows.
func newTestClientForClientCredentials(t *testing.T, mutate func(*client.Config)) (*client.Client, *fakeClientCredentialsAS) {
	t.Helper()
	as := &fakeClientCredentialsAS{t: t}
	ts := httptest.NewServer(as.handler())
	t.Cleanup(ts.Close)

	cfg := validConfig(t)
	tokenURL, err := fapi.ParseEndpointURL(ts.URL+"/token", fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseEndpointURL(token): %v", err)
	}
	cfg.Endpoints.Token = tokenURL
	if mutate != nil {
		mutate(&cfg)
	}

	deps := validDependencies(t)
	deps.HTTP = ts.Client()

	c, err := client.New(cfg, deps)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	return c, as
}

func TestRequestClientCredentialsTokenDPoPSuccess(t *testing.T) {
	c, as := newTestClientForClientCredentials(t, nil)

	result, err := c.RequestClientCredentialsToken(context.Background(), client.ClientCredentialsTokenRequest{
		Scope: []string{"accounts"},
		AuthorizationDetails: []json.RawMessage{
			json.RawMessage(`{"type":"payment_initiation","amount":10}`),
		},
	})
	if err != nil {
		t.Fatalf("RequestClientCredentialsToken: %v", err)
	}
	if result.AccessToken.Reveal() != "opaque-client-credentials-token" {
		t.Errorf("AccessToken = %q, want opaque-client-credentials-token", result.AccessToken.Reveal())
	}
	if result.TokenType != "DPoP" {
		t.Errorf("TokenType = %q, want DPoP", result.TokenType)
	}
	if result.Scope != "accounts" {
		t.Errorf("Scope = %q, want accounts", result.Scope)
	}
	if !result.HasExpiresIn || result.ExpiresIn.Seconds() != 300 {
		t.Errorf("ExpiresIn = %v (has=%v), want 300s", result.ExpiresIn, result.HasExpiresIn)
	}
	if string(result.AuthorizationDetails) == "" {
		t.Errorf("AuthorizationDetails is empty, want the echoed detail object")
	}

	if as.lastForm.Get("grant_type") != "client_credentials" {
		t.Errorf("grant_type = %q, want client_credentials", as.lastForm.Get("grant_type"))
	}
	if as.lastForm.Get("client_assertion") == "" {
		t.Errorf("client_assertion missing (ClientAuthMethodPrivateKeyJWT is the default)")
	}
	if !strings.HasPrefix(as.lastForm.Get("authorization_details"), "[") {
		t.Errorf("authorization_details = %q, want a JSON array", as.lastForm.Get("authorization_details"))
	}
}

// TestRequestClientCredentialsTokenSendsClientIDWhenNotPrivateKeyJWT
// covers buildForm's else branch: any RFC 8705 §2 ClientAuthMethod sends
// a plain client_id, never a client_assertion.
func TestRequestClientCredentialsTokenSendsClientIDWhenNotPrivateKeyJWT(t *testing.T) {
	c, as := newTestClientForClientCredentials(t, func(cfg *client.Config) {
		cfg.ClientAuthMethod = storage.ClientAuthMethodSelfSignedTLSClientAuth
	})

	if _, err := c.RequestClientCredentialsToken(context.Background(), client.ClientCredentialsTokenRequest{Scope: []string{"accounts"}}); err != nil {
		t.Fatalf("RequestClientCredentialsToken: %v", err)
	}
	if as.lastForm.Get("client_id") != testClientID {
		t.Errorf("client_id = %q, want %q", as.lastForm.Get("client_id"), testClientID)
	}
	if as.lastForm.Get("client_assertion") != "" {
		t.Errorf("client_assertion = %q, want empty under a non-private_key_jwt ClientAuthMethod", as.lastForm.Get("client_assertion"))
	}
}

// TestRequestClientCredentialsTokenMTLSSendsNoDPoPProof covers
// sendTokenRequest's SenderConstrainMTLS branch as reached from this
// call site, and tokenTypeFor's "Bearer" expectation.
func TestRequestClientCredentialsTokenMTLSSendsNoDPoPProof(t *testing.T) {
	c, as := newTestClientForClientCredentials(t, func(cfg *client.Config) {
		cfg.SenderConstrain = storage.SenderConstrainMTLS
		cfg.Algorithms.DPoP = 0
	})

	result, err := c.RequestClientCredentialsToken(context.Background(), client.ClientCredentialsTokenRequest{Scope: []string{"accounts"}})
	if err != nil {
		t.Fatalf("RequestClientCredentialsToken: %v", err)
	}
	if result.TokenType != "Bearer" {
		t.Errorf("TokenType = %q, want Bearer", result.TokenType)
	}
	if as.lastForm.Get("client_assertion") == "" {
		t.Errorf("client_assertion missing (ClientAuthMethod is still the default private_key_jwt)")
	}
}

func TestRequestClientCredentialsTokenRejectsWrongTokenType(t *testing.T) {
	c, as := newTestClientForClientCredentials(t, nil)
	as.tokenTypeOverride = "Bearer" // this client's SenderConstrain is DPoP (the default), so it expects "DPoP"

	if _, err := c.RequestClientCredentialsToken(context.Background(), client.ClientCredentialsTokenRequest{Scope: []string{"accounts"}}); err == nil {
		t.Fatalf("RequestClientCredentialsToken(wrong token_type) = nil error, want error")
	}
}

func TestRequestClientCredentialsTokenRejectsMalformedResponse(t *testing.T) {
	c, as := newTestClientForClientCredentials(t, nil)
	as.malformedResponse = true

	if _, err := c.RequestClientCredentialsToken(context.Background(), client.ClientCredentialsTokenRequest{Scope: []string{"accounts"}}); err == nil {
		t.Fatalf("RequestClientCredentialsToken(malformed response) = nil error, want error")
	}
}

func TestRequestClientCredentialsTokenPropagatesServerError(t *testing.T) {
	c, as := newTestClientForClientCredentials(t, nil)
	as.rejectPlain = true

	if _, err := c.RequestClientCredentialsToken(context.Background(), client.ClientCredentialsTokenRequest{Scope: []string{"accounts"}}); err == nil {
		t.Fatalf("RequestClientCredentialsToken(server error) = nil error, want error")
	}
}

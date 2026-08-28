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
	"github.com/idfoundry/fapigo/internal/requestobject"
	"github.com/idfoundry/fapigo/internal/token"
	"github.com/idfoundry/fapigo/keys"
)

// fakeCIBAAS simulates just enough of an authorization server's
// backchannel authentication and token endpoints to exercise client's
// CIBA wire format end to end — mirrors fakeAS's own scope (prove
// client builds a well-formed request and correctly interprets what
// comes back), for the CIBA endpoints instead of PAR/authorization-code.
type fakeCIBAAS struct {
	t          *testing.T
	idTokenKey *ecdsa.PrivateKey
	authReqID  string

	lastBCForm      url.Values
	lastBCDPoPProof string
	bcCallCount     int

	lastPollForm      url.Values
	lastPollDPoPProof string

	// challengeBCDPoPNonce, if non-empty, makes handleBackchannelAuth
	// reject every request whose DPoP proof doesn't carry this exact
	// "nonce" claim with RFC 9449 §8's use_dpop_nonce challenge.
	challengeBCDPoPNonce string

	// rejectBCRequestPlain, if true, makes handleBackchannelAuth
	// respond to every request with an ordinary (non-DPoP-nonce) error
	// — exercising BeginBackchannelAuthentication's non-retryable error
	// path, as opposed to challengeBCDPoPNonce's challenge/retry path.
	rejectBCRequestPlain bool

	// tokenResponses is a queue of canned responses handleToken pops
	// from, in order — lets a test script a sequence of polls (e.g.
	// pending, then approved) across successive
	// PollBackchannelAuthentication calls.
	tokenResponses []cibaTokenResponse
}

type cibaTokenResponse struct {
	status int
	body   map[string]any
}

func newFakeCIBAAS(t *testing.T) *fakeCIBAAS {
	t.Helper()
	idKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate id token key: %v", err)
	}
	return &fakeCIBAAS{t: t, idTokenKey: idKey, authReqID: "test-auth-req-id"}
}

func (a *fakeCIBAAS) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/backchannel-authenticate", a.handleBackchannelAuth)
	mux.HandleFunc("/token", a.handleToken)
	return mux
}

func (a *fakeCIBAAS) handleBackchannelAuth(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.t.Fatalf("backchannel-authenticate: parse form: %v", err)
	}
	a.lastBCForm = r.PostForm
	a.bcCallCount++
	proof := r.Header.Get("DPoP")
	a.lastBCDPoPProof = proof
	if r.PostForm.Get("client_assertion") == "" {
		a.t.Errorf("backchannel-authenticate: missing client_assertion")
	}
	if r.PostForm.Get("request") == "" {
		a.t.Errorf("backchannel-authenticate: missing signed request object")
	}

	if a.rejectBCRequestPlain {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{
			"error":             "invalid_client",
			"error_description": "test: rejected without a DPoP-nonce challenge",
		})
		return
	}

	if a.challengeBCDPoPNonce != "" && dpopProofNonce(a.t, proof) != a.challengeBCDPoPNonce {
		w.Header().Set("DPoP-Nonce", a.challengeBCDPoPNonce)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{
			"error":             "use_dpop_nonce",
			"error_description": "resubmit with the DPoP-Nonce value",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"auth_req_id": a.authReqID,
		"expires_in":  120,
		"interval":    5,
	})
}

func (a *fakeCIBAAS) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.t.Fatalf("token: parse form: %v", err)
	}
	a.lastPollForm = r.PostForm
	a.lastPollDPoPProof = r.Header.Get("DPoP")
	if r.PostForm.Get("grant_type") != "urn:openid:params:grant-type:ciba" {
		a.t.Errorf("token: grant_type = %q, want CIBA grant type", r.PostForm.Get("grant_type"))
	}
	if r.PostForm.Get("client_assertion") == "" {
		a.t.Errorf("token: missing client_assertion")
	}
	if a.lastPollDPoPProof == "" {
		a.t.Errorf("token: missing DPoP header")
	}

	if len(a.tokenResponses) == 0 {
		a.t.Fatalf("token: no canned response queued")
	}
	resp := a.tokenResponses[0]
	a.tokenResponses = a.tokenResponses[1:]

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.status)
	json.NewEncoder(w).Encode(resp.body)
}

// newTestClientWithCIBA is validConfig/validDependencies plus CIBA
// wiring (Endpoints.BackchannelAuthentication, Algorithms.BackchannelAuthenticationRequest,
// Limits.BackchannelAuthenticationRequestLifetime) against a
// fakeCIBAAS-backed httptest.Server.
func newTestClientWithCIBA(t *testing.T) (*client.Client, *fakeCIBAAS, *httptest.Server) {
	t.Helper()
	as := newFakeCIBAAS(t)
	ts := httptest.NewServer(as.handler())
	t.Cleanup(ts.Close)

	cfg := validConfig(t)
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
	deps.Keys = newFakeKeyManager(t,
		keys.ClientAuthentication, keys.DPoPProofSigning, keys.BackchannelAuthenticationRequestSigning)
	deps.IssuerKeys = &fakeIssuerKeySource{keys: map[keys.IssuerVerificationPurpose]crypto.PublicKey{
		keys.IDTokenVerification: &as.idTokenKey.PublicKey,
	}}

	c, err := client.New(cfg, deps)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	return c, as, ts
}

func TestBeginBackchannelAuthenticationRejectsNoHint(t *testing.T) {
	c, _, _ := newTestClientWithCIBA(t)
	_, err := c.BeginBackchannelAuthentication(context.Background(), client.BeginBackchannelAuthenticationRequest{
		Scope: []string{"openid"},
	})
	if err == nil {
		t.Fatalf("BeginBackchannelAuthentication(no hint) = nil error, want error")
	}
	cerr, ok := err.(*client.Error)
	if !ok || cerr.Code() != client.ErrorInvalidRequest {
		t.Fatalf("error = %v, want *client.Error{Code: ErrorInvalidRequest}", err)
	}
}

func TestBeginBackchannelAuthenticationRejectsMultipleHints(t *testing.T) {
	c, _, _ := newTestClientWithCIBA(t)
	_, err := c.BeginBackchannelAuthentication(context.Background(), client.BeginBackchannelAuthenticationRequest{
		Scope: []string{"openid"}, LoginHint: "user@example.com", IDTokenHint: "some-id-token",
	})
	if err == nil {
		t.Fatalf("BeginBackchannelAuthentication(two hints) = nil error, want error")
	}
	cerr, ok := err.(*client.Error)
	if !ok || cerr.Code() != client.ErrorInvalidRequest {
		t.Fatalf("error = %v, want *client.Error{Code: ErrorInvalidRequest}", err)
	}
}

func TestBeginBackchannelAuthenticationHappyPath(t *testing.T) {
	c, as, _ := newTestClientWithCIBA(t)

	session, err := c.BeginBackchannelAuthentication(context.Background(), client.BeginBackchannelAuthenticationRequest{
		Scope:           []string{"openid", "accounts"},
		LoginHint:       "user@example.com",
		ACRValues:       []string{"urn:mace:incommon:iap:silver"},
		BindingMessage:  "W4SCT",
		RequestedExpiry: 90 * time.Second,
	})
	if err != nil {
		t.Fatalf("BeginBackchannelAuthentication: %v", err)
	}
	if session.AuthReqID() != as.authReqID {
		t.Errorf("AuthReqID() = %q, want %q", session.AuthReqID(), as.authReqID)
	}
	if session.Interval() != 5*time.Second {
		t.Errorf("Interval() = %v, want 5s", session.Interval())
	}
	if session.ExpiresAt().IsZero() {
		t.Errorf("ExpiresAt() is zero, want a populated deadline")
	}

	if as.lastBCForm.Get("client_assertion") == "" {
		t.Errorf("client_assertion missing from backchannel authentication request")
	}
	if as.lastBCDPoPProof == "" {
		t.Errorf("DPoP proof missing from backchannel authentication request")
	}

	requestJWT := as.lastBCForm.Get("request")
	if requestJWT == "" {
		t.Fatalf("request (signed request object) missing")
	}
	obj, err := requestobject.Parse(requestJWT)
	if err != nil {
		t.Fatalf("parse request object: %v", err)
	}
	if obj.ClaimedIssuer() != testClientID {
		t.Errorf("request object client_id (iss) = %q, want %q", obj.ClaimedIssuer(), testClientID)
	}

	wantStrings := map[string]string{
		"scope":           "openid accounts",
		"login_hint":      "user@example.com",
		"acr_values":      "urn:mace:incommon:iap:silver",
		"binding_message": "W4SCT",
	}
	for name, want := range wantStrings {
		raw, ok := obj.Parameter(name)
		if !ok {
			t.Errorf("request object missing %q claim", name)
			continue
		}
		var got string
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Errorf("%q claim is not a string: %v", name, err)
			continue
		}
		if got != want {
			t.Errorf("%q = %q, want %q", name, got, want)
		}
	}
	requestedExpiryRaw, ok := obj.Parameter("requested_expiry")
	if !ok {
		t.Fatalf("request object missing requested_expiry claim")
	}
	var requestedExpiry int64
	if err := json.Unmarshal(requestedExpiryRaw, &requestedExpiry); err != nil {
		t.Fatalf("requested_expiry claim is not a number: %v", err)
	}
	if requestedExpiry != 90 {
		t.Errorf("requested_expiry = %d, want 90", requestedExpiry)
	}
}

func TestBeginBackchannelAuthenticationRetriesOnDPoPNonceChallenge(t *testing.T) {
	c, as, _ := newTestClientWithCIBA(t)
	as.challengeBCDPoPNonce = "test-bc-nonce"

	session, err := c.BeginBackchannelAuthentication(context.Background(), client.BeginBackchannelAuthenticationRequest{
		Scope: []string{"openid"}, LoginHint: "user@example.com",
	})
	if err != nil {
		t.Fatalf("BeginBackchannelAuthentication: %v", err)
	}
	if as.bcCallCount != 2 {
		t.Errorf("bcCallCount = %d, want 2 (initial + nonce retry)", as.bcCallCount)
	}
	if session.AuthReqID() != as.authReqID {
		t.Errorf("AuthReqID() = %q, want %q", session.AuthReqID(), as.authReqID)
	}
	if got := dpopProofNonce(t, as.lastBCDPoPProof); got != as.challengeBCDPoPNonce {
		t.Errorf("retry DPoP proof nonce = %q, want %q", got, as.challengeBCDPoPNonce)
	}
}

func TestBeginBackchannelAuthenticationRejectsHTTPError(t *testing.T) {
	c, as, _ := newTestClientWithCIBA(t)
	as.rejectBCRequestPlain = true

	_, err := c.BeginBackchannelAuthentication(context.Background(), client.BeginBackchannelAuthenticationRequest{
		Scope: []string{"openid"}, LoginHint: "user@example.com",
	})
	if err == nil {
		t.Fatalf("BeginBackchannelAuthentication = nil error, want error")
	}
	cerr, ok := err.(*client.Error)
	if !ok {
		t.Fatalf("error type = %T, want *client.Error", err)
	}
	if cerr.Code() != client.ErrorInvalidResponse {
		t.Errorf("Code() = %q, want %q", cerr.Code(), client.ErrorInvalidResponse)
	}
}

func newCIBAIDToken(t *testing.T, as *fakeCIBAAS) string {
	t.Helper()
	idToken, err := token.IssueIDToken(token.IDTokenParams{
		Signer: as.idTokenKey, Algorithm: fapi.ES256, KeyID: "as-id-kid",
		Issuer: testIssuer, Subject: "end-user-1", Audience: testClientID,
		Now: time.Now(), Lifetime: time.Minute,
	})
	if err != nil {
		t.Fatalf("issue id token: %v", err)
	}
	return idToken
}

func beginTestBackchannelSession(t *testing.T, c *client.Client) client.BackchannelAuthenticationSession {
	t.Helper()
	session, err := c.BeginBackchannelAuthentication(context.Background(), client.BeginBackchannelAuthenticationRequest{
		Scope: []string{"openid", "accounts"}, LoginHint: "user@example.com",
	})
	if err != nil {
		t.Fatalf("BeginBackchannelAuthentication: %v", err)
	}
	return session
}

func TestPollBackchannelAuthenticationApproved(t *testing.T) {
	c, as, _ := newTestClientWithCIBA(t)
	session := beginTestBackchannelSession(t, c)

	as.tokenResponses = []cibaTokenResponse{{
		status: http.StatusOK,
		body: map[string]any{
			"access_token":  "opaque-access-token",
			"token_type":    "DPoP",
			"expires_in":    300,
			"scope":         "openid accounts",
			"id_token":      newCIBAIDToken(t, as),
			"refresh_token": "opaque-refresh-token",
		},
	}}

	result, err := c.PollBackchannelAuthentication(context.Background(), session)
	if err != nil {
		t.Fatalf("PollBackchannelAuthentication: %v", err)
	}
	approved, ok := result.(client.BackchannelAuthenticationApproved)
	if !ok {
		t.Fatalf("result type = %T, want client.BackchannelAuthenticationApproved", result)
	}
	if approved.Tokens.AccessToken.Reveal() != "opaque-access-token" {
		t.Errorf("AccessToken = %q", approved.Tokens.AccessToken.Reveal())
	}
	if !approved.Tokens.HasIDToken {
		t.Fatalf("HasIDToken = false, want true")
	}
	if approved.Tokens.Subject != "end-user-1" {
		t.Errorf("Subject = %q, want %q", approved.Tokens.Subject, "end-user-1")
	}
	if !approved.Tokens.HasRefreshToken || approved.Tokens.RefreshToken.Reveal() != "opaque-refresh-token" {
		t.Errorf("RefreshToken not populated correctly: %+v", approved.Tokens)
	}
	if as.lastPollForm.Get("auth_req_id") != session.AuthReqID() {
		t.Errorf("polled auth_req_id = %q, want %q", as.lastPollForm.Get("auth_req_id"), session.AuthReqID())
	}
}

func TestPollBackchannelAuthenticationPending(t *testing.T) {
	c, as, _ := newTestClientWithCIBA(t)
	session := beginTestBackchannelSession(t, c)

	as.tokenResponses = []cibaTokenResponse{{
		status: http.StatusBadRequest,
		body:   map[string]any{"error": "authorization_pending"},
	}}

	result, err := c.PollBackchannelAuthentication(context.Background(), session)
	if err != nil {
		t.Fatalf("PollBackchannelAuthentication: %v", err)
	}
	pending, ok := result.(client.BackchannelAuthenticationPending)
	if !ok {
		t.Fatalf("result type = %T, want client.BackchannelAuthenticationPending", result)
	}
	if pending.SlowDown {
		t.Errorf("SlowDown = true, want false for authorization_pending")
	}
}

func TestPollBackchannelAuthenticationSlowDown(t *testing.T) {
	c, as, _ := newTestClientWithCIBA(t)
	session := beginTestBackchannelSession(t, c)

	as.tokenResponses = []cibaTokenResponse{{
		status: http.StatusBadRequest,
		body:   map[string]any{"error": "slow_down"},
	}}

	result, err := c.PollBackchannelAuthentication(context.Background(), session)
	if err != nil {
		t.Fatalf("PollBackchannelAuthentication: %v", err)
	}
	pending, ok := result.(client.BackchannelAuthenticationPending)
	if !ok {
		t.Fatalf("result type = %T, want client.BackchannelAuthenticationPending", result)
	}
	if !pending.SlowDown {
		t.Errorf("SlowDown = false, want true for slow_down")
	}
}

func TestPollBackchannelAuthenticationDenied(t *testing.T) {
	c, as, _ := newTestClientWithCIBA(t)
	session := beginTestBackchannelSession(t, c)

	as.tokenResponses = []cibaTokenResponse{{
		status: http.StatusBadRequest,
		body:   map[string]any{"error": "access_denied", "error_description": "the end user denied the request"},
	}}

	result, err := c.PollBackchannelAuthentication(context.Background(), session)
	if err != nil {
		t.Fatalf("PollBackchannelAuthentication: %v", err)
	}
	denied, ok := result.(client.BackchannelAuthenticationDenied)
	if !ok {
		t.Fatalf("result type = %T, want client.BackchannelAuthenticationDenied", result)
	}
	if denied.Code != "access_denied" {
		t.Errorf("Code = %q, want %q", denied.Code, "access_denied")
	}
	if denied.Description != "the end user denied the request" {
		t.Errorf("Description = %q", denied.Description)
	}
}

func TestPollBackchannelAuthenticationExpired(t *testing.T) {
	c, as, _ := newTestClientWithCIBA(t)
	session := beginTestBackchannelSession(t, c)

	as.tokenResponses = []cibaTokenResponse{{
		status: http.StatusBadRequest,
		body:   map[string]any{"error": "expired_token"},
	}}

	result, err := c.PollBackchannelAuthentication(context.Background(), session)
	if err != nil {
		t.Fatalf("PollBackchannelAuthentication: %v", err)
	}
	if _, ok := result.(client.BackchannelAuthenticationExpired); !ok {
		t.Fatalf("result type = %T, want client.BackchannelAuthenticationExpired", result)
	}
}

// TestPollBackchannelAuthenticationUnknownAuthReqIDIsARealError covers
// the fallthrough branch: an OAuth error code PollBackchannelAuthentication
// doesn't specifically recognize (invalid_grant, the code a real server
// returns for an unknown or already-redeemed auth_req_id) must surface
// as a real *client.Error, not one of the four expected-outcome result
// variants.
func TestPollBackchannelAuthenticationUnknownAuthReqIDIsARealError(t *testing.T) {
	c, as, _ := newTestClientWithCIBA(t)
	session := beginTestBackchannelSession(t, c)

	as.tokenResponses = []cibaTokenResponse{{
		status: http.StatusBadRequest,
		body:   map[string]any{"error": "invalid_grant", "error_description": "auth_req_id is invalid or unknown"},
	}}

	result, err := c.PollBackchannelAuthentication(context.Background(), session)
	if err == nil {
		t.Fatalf("PollBackchannelAuthentication(invalid_grant) = nil error, want error; result = %v", result)
	}
	cerr, ok := err.(*client.Error)
	if !ok {
		t.Fatalf("error type = %T, want *client.Error", err)
	}
	if cerr.Code() != client.ErrorInvalidResponse {
		t.Errorf("Code() = %q, want %q", cerr.Code(), client.ErrorInvalidResponse)
	}
}

package client_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/internal/jarm"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/internal/requestobject"
	"github.com/idfoundry/fapigo/internal/token"
	"github.com/idfoundry/fapigo/keys"
)

// fakeAS simulates just enough of an authorization server's PAR and
// token endpoints to exercise client's wire format end to end: it does
// not verify the client's DPoP proof or client assertion signatures
// (server's own tests already cover that verification logic
// exhaustively) — it exists to prove client builds a well-formed
// request and correctly verifies what comes back, particularly JARM and
// ID token validation.
type fakeAS struct {
	t             *testing.T
	jarmKey       *ecdsa.PrivateKey
	idTokenKey    *ecdsa.PrivateKey
	issuer        string
	messageSigned bool

	lastPARForm        url.Values
	lastTokenForm      url.Values
	lastTokenDPoPProof string
	lastNonce          string

	// challengeDPoPNonce, if non-empty, makes handleToken reject every
	// token request whose DPoP proof doesn't carry this exact "nonce"
	// claim with RFC 9449 §8's use_dpop_nonce challenge - the same shape
	// a real DPoP-nonce-requiring authorization server uses.
	challengeDPoPNonce   string
	tokenCallCount       int
	seenClientAssertions map[string]bool

	// tokenTypeOverride, if non-empty, replaces the token response's
	// token_type value (e.g. "dpop" lowercase, to test RFC 6749 §7.1's
	// "Values are case insensitive").
	tokenTypeOverride string

	// omitExpiresIn drops expires_in from the token response entirely,
	// to test that a client tolerates its absence (RFC 6749 §5.1:
	// RECOMMENDED, not REQUIRED).
	omitExpiresIn bool
}

func newFakeAS(t *testing.T, issuer string, messageSigned bool) *fakeAS {
	t.Helper()
	jarmKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate jarm key: %v", err)
	}
	idKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate id token key: %v", err)
	}
	return &fakeAS{t: t, jarmKey: jarmKey, idTokenKey: idKey, issuer: issuer, messageSigned: messageSigned}
}

func (a *fakeAS) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/par", a.handlePAR)
	mux.HandleFunc("/token", a.handleToken)
	return mux
}

func (a *fakeAS) handlePAR(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.t.Fatalf("PAR: parse form: %v", err)
	}
	a.lastPARForm = r.PostForm
	if r.PostForm.Get("client_assertion") == "" {
		a.t.Errorf("PAR: missing client_assertion")
	}
	if a.messageSigned {
		requestJWT := r.PostForm.Get("request")
		if requestJWT == "" {
			a.t.Errorf("PAR: missing signed request object under message-signing profile")
		} else {
			obj, err := requestobject.Parse(requestJWT)
			if err != nil {
				a.t.Errorf("PAR: parse request object: %v", err)
			} else if nonceRaw, ok := obj.Parameter("nonce"); ok {
				json.Unmarshal(nonceRaw, &a.lastNonce)
			}
		}
	} else {
		if r.PostForm.Get("code_challenge") == "" {
			a.t.Errorf("PAR: missing code_challenge under baseline profile")
		}
		a.lastNonce = r.PostForm.Get("nonce")
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{
		"request_uri": "urn:ietf:params:oauth:request_uri:abc123",
		"expires_in":  60,
	})
}

// callbackFor builds the query string a real authorization server would
// redirect back with, for the given outcome, using the state captured
// from session.Handle(). code == "" produces an error response instead
// of a success one.
func (a *fakeAS) callbackFor(t *testing.T, state, code, errCode string) string {
	t.Helper()
	params := map[string]string{"state": state}
	if code != "" {
		params["code"] = code
	} else {
		params["error"] = errCode
		params["error_description"] = "denied by test"
	}

	if !a.messageSigned {
		q := url.Values{}
		for k, v := range params {
			q.Set(k, v)
		}
		q.Set("iss", a.issuer)
		return q.Encode()
	}

	jsonParams := make(map[string]json.RawMessage, len(params))
	for k, v := range params {
		encoded, _ := json.Marshal(v)
		jsonParams[k] = encoded
	}
	responseJWT, err := jarm.Create(jarm.CreateParams{
		Signer: a.jarmKey, Algorithm: fapi.ES256, KeyID: "as-jarm-kid",
		Issuer: a.issuer, Audience: testClientID,
		Now: time.Now(), Lifetime: time.Minute, Parameters: jsonParams,
	})
	if err != nil {
		t.Fatalf("sign jarm response: %v", err)
	}
	q := url.Values{}
	q.Set("response", responseJWT)
	return q.Encode()
}

func (a *fakeAS) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.t.Fatalf("token: parse form: %v", err)
	}
	a.lastTokenForm = r.PostForm
	a.tokenCallCount++
	proof := r.Header.Get("DPoP")
	if proof == "" {
		a.t.Errorf("token: missing DPoP header")
	}
	a.lastTokenDPoPProof = proof

	// A client assertion is exactly as single-use as a DPoP proof: reject
	// reuse the same way a real jti-tracking authorization server (this
	// module's own server package included) would, so a retry that
	// forgets to sign a fresh assertion fails this test the same way it
	// fails against the real suite.
	if assertion := r.PostForm.Get("client_assertion"); assertion != "" {
		if a.seenClientAssertions == nil {
			a.seenClientAssertions = make(map[string]bool)
		}
		if a.seenClientAssertions[assertion] {
			a.t.Errorf("token: client_assertion reused across requests")
		}
		a.seenClientAssertions[assertion] = true
	}
	if r.PostForm.Get("code_verifier") == "" {
		a.t.Errorf("token: missing code_verifier")
	}

	if a.challengeDPoPNonce != "" && dpopProofNonce(a.t, proof) != a.challengeDPoPNonce {
		w.Header().Set("DPoP-Nonce", a.challengeDPoPNonce)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{
			"error":             "use_dpop_nonce",
			"error_description": "resubmit with the DPoP-Nonce value",
		})
		return
	}

	idToken, err := token.IssueIDToken(token.IDTokenParams{
		Signer: a.idTokenKey, Algorithm: fapi.ES256, KeyID: "as-id-kid",
		Issuer: a.issuer, Subject: "end-user-1", Audience: testClientID,
		Nonce: a.lastNonce, Now: time.Now(), Lifetime: time.Minute,
	})
	if err != nil {
		a.t.Fatalf("issue id token: %v", err)
	}

	tokenType := "DPoP"
	if a.tokenTypeOverride != "" {
		tokenType = a.tokenTypeOverride
	}
	resp := map[string]any{
		"access_token":  "opaque-access-token",
		"token_type":    tokenType,
		"scope":         "openid accounts",
		"id_token":      idToken,
		"refresh_token": "opaque-refresh-token",
	}
	if !a.omitExpiresIn {
		resp["expires_in"] = 300
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func newTestClient(t *testing.T, messageSigned bool) (*client.Client, *fakeAS, *httptest.Server) {
	t.Helper()
	as := newFakeAS(t, testIssuer, messageSigned)
	ts := httptest.NewServer(as.handler())
	t.Cleanup(ts.Close)

	cfg := validConfig(t)
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
		keys.JARMVerification:    &as.jarmKey.PublicKey,
		keys.IDTokenVerification: &as.idTokenKey.PublicKey,
	}}

	if messageSigned {
		cfg.Profile = client.ProfileFAPISecurityWithMessageSigning
		cfg.Algorithms.RequestObject = fapi.ES256
		cfg.Algorithms.JARM = fapi.ES256
		cfg.Limits.RequestObjectLifetime = time.Minute
		cfg.Limits.MaxJARMResponseLifetime = time.Minute
	}

	c, err := client.New(cfg, deps)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	return c, as, ts
}

// dpopProofNonce extracts the "nonce" claim from a DPoP proof's payload
// without verifying its signature — this test only needs to observe
// what the client sent, not re-validate cryptography internal/dpop's
// own tests already cover.
func dpopProofNonce(t *testing.T, proof string) string {
	t.Helper()
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatalf("DPoP proof is not a 3-part JWT: %q", proof)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode DPoP proof payload: %v", err)
	}
	var claims struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal DPoP proof claims: %v", err)
	}
	return claims.Nonce
}

// dpopProofJKT extracts the embedded "jwk" from a DPoP proof's header
// and returns its RFC 7638 thumbprint — the same value a server would
// compare against an authorization request's "dpop_jkt" parameter
// (RFC 9449 §10) — without verifying the proof's signature, for the
// same reason dpopProofNonce doesn't.
func dpopProofJKT(t *testing.T, proof string) string {
	t.Helper()
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatalf("DPoP proof is not a 3-part JWT: %q", proof)
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode DPoP proof header: %v", err)
	}
	var parsed struct {
		JWK json.RawMessage `json:"jwk"`
	}
	if err := json.Unmarshal(header, &parsed); err != nil {
		t.Fatalf("unmarshal DPoP proof header: %v", err)
	}
	jwk, err := jose.ParseJWK(parsed.JWK, fapi.ES256)
	if err != nil {
		t.Fatalf("parse DPoP proof jwk: %v", err)
	}
	thumbprint, err := jwk.Thumbprint()
	if err != nil {
		t.Fatalf("compute DPoP proof jwk thumbprint: %v", err)
	}
	return thumbprint.String()
}

// RFC 9449 §8: an authorization server that requires a DPoP nonce
// rejects a proof lacking one with use_dpop_nonce and a DPoP-Nonce
// response header naming the value to use; the client is expected to
// retry once with a fresh proof carrying it.
func TestExchangeCodeRetriesOnDPoPNonceChallenge(t *testing.T) {
	c, as, _ := newTestClient(t, false)
	as.challengeDPoPNonce = "server-issued-nonce-1"
	ctx := context.Background()

	session, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid", "accounts"}})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}

	rawQuery := as.callbackFor(t, session.Handle().String(), "auth-code-123", "")
	result, err := c.CompleteAuthorization(ctx, client.AuthorizationCallback{RawQuery: rawQuery})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	success, ok := result.(client.CompletionSuccess)
	if !ok {
		t.Fatalf("result type = %T, want client.CompletionSuccess", result)
	}
	if success.Tokens.AccessToken.Reveal() != "opaque-access-token" {
		t.Errorf("AccessToken = %q", success.Tokens.AccessToken.Reveal())
	}
	if as.tokenCallCount != 2 {
		t.Errorf("token endpoint called %d times, want 2 (initial + nonce retry)", as.tokenCallCount)
	}
}

// RFC 6749 §7.1: "The type of the token issued... Value is case
// insensitive."
func TestExchangeCodeAcceptsCaseInsensitiveTokenType(t *testing.T) {
	c, as, _ := newTestClient(t, false)
	as.tokenTypeOverride = "dpop"
	ctx := context.Background()

	session, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid", "accounts"}})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	rawQuery := as.callbackFor(t, session.Handle().String(), "auth-code-123", "")
	result, err := c.CompleteAuthorization(ctx, client.AuthorizationCallback{RawQuery: rawQuery})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	success, ok := result.(client.CompletionSuccess)
	if !ok {
		t.Fatalf("result type = %T, want client.CompletionSuccess", result)
	}
	if success.Tokens.TokenType != "DPoP" {
		t.Errorf("TokenType = %q, want canonical %q regardless of the server's casing", success.Tokens.TokenType, "DPoP")
	}
}

// RFC 6749 §5.1 marks expires_in RECOMMENDED, not REQUIRED, and
// explicitly permits an authorization server to omit it and document a
// default lifetime out of band instead.
func TestExchangeCodeToleratesMissingExpiresIn(t *testing.T) {
	c, as, _ := newTestClient(t, false)
	as.omitExpiresIn = true
	ctx := context.Background()

	session, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid", "accounts"}})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	rawQuery := as.callbackFor(t, session.Handle().String(), "auth-code-123", "")
	result, err := c.CompleteAuthorization(ctx, client.AuthorizationCallback{RawQuery: rawQuery})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	success, ok := result.(client.CompletionSuccess)
	if !ok {
		t.Fatalf("result type = %T, want client.CompletionSuccess", result)
	}
	if success.Tokens.HasExpiresIn {
		t.Errorf("HasExpiresIn = true, want false when the server omitted expires_in")
	}
}

func TestCompleteAuthorizationHappyPathBaseline(t *testing.T) {
	c, as, _ := newTestClient(t, false)
	ctx := context.Background()

	session, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid", "accounts"}})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}

	rawQuery := as.callbackFor(t, session.Handle().String(), "auth-code-123", "")
	result, err := c.CompleteAuthorization(ctx, client.AuthorizationCallback{RawQuery: rawQuery})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	success, ok := result.(client.CompletionSuccess)
	if !ok {
		t.Fatalf("result type = %T, want client.CompletionSuccess", result)
	}
	if success.Tokens.AccessToken.Reveal() != "opaque-access-token" {
		t.Errorf("AccessToken = %q", success.Tokens.AccessToken.Reveal())
	}
	if !success.Tokens.HasIDToken || success.Tokens.Subject != "end-user-1" {
		t.Errorf("HasIDToken=%v Subject=%q, want true/end-user-1", success.Tokens.HasIDToken, success.Tokens.Subject)
	}
	if !success.Tokens.HasRefreshToken {
		t.Errorf("HasRefreshToken = false, want true")
	}
}

func TestCompleteAuthorizationHappyPathMessageSigning(t *testing.T) {
	c, as, _ := newTestClient(t, true)
	ctx := context.Background()

	session, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid", "accounts"}})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}

	rawQuery := as.callbackFor(t, session.Handle().String(), "auth-code-456", "")
	result, err := c.CompleteAuthorization(ctx, client.AuthorizationCallback{RawQuery: rawQuery})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	success, ok := result.(client.CompletionSuccess)
	if !ok {
		t.Fatalf("result type = %T, want client.CompletionSuccess", result)
	}
	if success.Tokens.Subject != "end-user-1" {
		t.Errorf("Subject = %q, want end-user-1", success.Tokens.Subject)
	}
}

// ACRValues is opt-in and off by default (many authorization servers
// reject acr_values outright for a client not specifically provisioned
// for it) — sent as the standard OIDC Core §3.1.2.1 space-separated
// list only when the caller actually sets it.
func TestBeginAuthorizationOmitsACRValuesByDefault(t *testing.T) {
	c, as, _ := newTestClient(t, false)
	if _, err := c.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{Scope: []string{"openid"}}); err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	if _, present := as.lastPARForm["acr_values"]; present {
		t.Errorf("PAR form contains acr_values %q, want it omitted when not requested", as.lastPARForm.Get("acr_values"))
	}
}

func TestBeginAuthorizationSendsRequestedACRValues(t *testing.T) {
	c, as, _ := newTestClient(t, false)
	req := client.BeginAuthorizationRequest{Scope: []string{"openid"}, ACRValues: []string{"urn:mace:incommon:iap:silver", "urn:mace:incommon:iap:bronze"}}
	if _, err := c.BeginAuthorization(context.Background(), req); err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	want := "urn:mace:incommon:iap:silver urn:mace:incommon:iap:bronze"
	if got := as.lastPARForm.Get("acr_values"); got != want {
		t.Errorf("PAR form acr_values = %q, want %q", got, want)
	}
}

// RFC 9126 §2 requires client_id on a pushed authorization request even
// though this client also authenticates via client_assertion — a strict
// authorization server may reject a PAR body that omits it.
func TestBeginAuthorizationSendsClientIDOnPlainPath(t *testing.T) {
	c, as, _ := newTestClient(t, false)
	if _, err := c.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{Scope: []string{"openid"}}); err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	if got := as.lastPARForm.Get("client_id"); got != testClientID {
		t.Errorf("PAR form client_id = %q, want %q", got, testClientID)
	}
}

// client_id belongs in the request object on the signing path (it
// already did before this change); this pins that it still does now
// that both paths build client_id from the same shared params map.
func TestBeginAuthorizationSendsClientIDInSignedRequestObject(t *testing.T) {
	c, as, _ := newTestClient(t, true)
	if _, err := c.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{Scope: []string{"openid"}}); err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	obj, err := requestobject.Parse(as.lastPARForm.Get("request"))
	if err != nil {
		t.Fatalf("parse request object: %v", err)
	}
	if obj.ClaimedIssuer() != testClientID {
		t.Errorf("request object client_id (iss) = %q, want %q", obj.ClaimedIssuer(), testClientID)
	}
}

// RFC 9449 §10: committing the DPoP key binding at PAR time (rather
// than leaving it to whichever key first shows up at the token
// endpoint) closes an authorization-code-injection window. This is the
// full round trip: the "dpop_jkt" sent at PAR must be the thumbprint of
// the exact key this client later presents a DPoP proof with at the
// token endpoint for the same authorization.
func TestBeginAuthorizationCommitsDPoPKeyAtPARMatchingTokenEndpointProof(t *testing.T) {
	c, as, _ := newTestClient(t, false)
	ctx := context.Background()

	session, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid"}})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	parJKT := as.lastPARForm.Get("dpop_jkt")
	if parJKT == "" {
		t.Fatalf("PAR form is missing dpop_jkt")
	}

	rawQuery := as.callbackFor(t, session.Handle().String(), "auth-code-dpop-jkt", "")
	if _, err := c.CompleteAuthorization(ctx, client.AuthorizationCallback{RawQuery: rawQuery}); err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}

	tokenJKT := dpopProofJKT(t, as.lastTokenDPoPProof)
	if tokenJKT != parJKT {
		t.Errorf("token endpoint DPoP proof key thumbprint = %q, want it to match PAR's dpop_jkt %q", tokenJKT, parJKT)
	}
}

// A JARM response carries no top-level "iss" query parameter — iss
// lives inside the signed JWT claims instead, verified as part of
// jarm.Verify — so RequireAuthorizationResponseIss must not reject a
// legitimate JARM callback as "missing iss" the way it would a plain
// one. Regression test for the bug where internal/jarm's Claims parsing
// pops "iss" out of Parameters entirely, making the RFC 9207 plain-mode
// check in HandleAuthorizationResponse see every JARM response as
// missing iss regardless of the token's actual, verified claims.
func TestCompleteAuthorizationMessageSigningSucceedsWithRequireAuthorizationResponseIss(t *testing.T) {
	as := newFakeAS(t, testIssuer, true)
	ts := httptest.NewServer(as.handler())
	t.Cleanup(ts.Close)

	cfg := validConfig(t)
	cfg.RequireAuthorizationResponseIss = true
	cfg.Profile = client.ProfileFAPISecurityWithMessageSigning
	cfg.Algorithms.RequestObject = fapi.ES256
	cfg.Algorithms.JARM = fapi.ES256
	cfg.Limits.RequestObjectLifetime = time.Minute
	cfg.Limits.MaxJARMResponseLifetime = time.Minute
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
		keys.JARMVerification:    &as.jarmKey.PublicKey,
		keys.IDTokenVerification: &as.idTokenKey.PublicKey,
	}}

	c, err := client.New(cfg, deps)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	ctx := context.Background()

	session, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid"}})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}

	rawQuery := as.callbackFor(t, session.Handle().String(), "auth-code-jarm-iss-required", "")
	result, err := c.CompleteAuthorization(ctx, client.AuthorizationCallback{RawQuery: rawQuery})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	if _, ok := result.(client.CompletionSuccess); !ok {
		t.Fatalf("result type = %T, want client.CompletionSuccess", result)
	}
}

// keys.JWKSIssuerKeySource's rate-limited unknown-kid path can return
// zero keys with no error (see keys/jwksissuer.go's
// ResolveIssuerKeys). Unlike the ID-token path (exchange_code.go),
// which rejects this explicitly, the JARM path used to have no
// equivalent guard: the verification loop over zero candidates never
// ran, verifyErr stayed nil, and parseCallbackParams returned a nil
// Parameters map — fail-closed only because a distant downstream check
// (HandleAuthorizationResponse reading "state" from nil params) happened
// to reject it as "callback is missing state". This test pins the fix:
// an explicit, correctly-typed ErrorInvalidResponse naming the actual
// problem, not a misleading error about a missing parameter.
func TestHandleAuthorizationResponseRejectsEmptyIssuerKeySetForJARM(t *testing.T) {
	as := newFakeAS(t, testIssuer, true)
	ts := httptest.NewServer(as.handler())
	t.Cleanup(ts.Close)

	cfg := validConfig(t)
	cfg.Profile = client.ProfileFAPISecurityWithMessageSigning
	cfg.Algorithms.RequestObject = fapi.ES256
	cfg.Algorithms.JARM = fapi.ES256
	cfg.Limits.RequestObjectLifetime = time.Minute
	cfg.Limits.MaxJARMResponseLifetime = time.Minute
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
	deps.IssuerKeys = emptyIssuerKeySource{}

	c, err := client.New(cfg, deps)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	ctx := context.Background()

	session, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid"}})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}

	rawQuery := as.callbackFor(t, session.Handle().String(), "auth-code-empty-keyset", "")
	_, err = c.HandleAuthorizationResponse(ctx, client.AuthorizationCallback{RawQuery: rawQuery})
	if err == nil {
		t.Fatalf("HandleAuthorizationResponse(empty issuer keyset) = nil error, want error")
	}
	cerr, ok := err.(*client.Error)
	if !ok {
		t.Fatalf("error type = %T, want *client.Error", err)
	}
	if cerr.Code() != client.ErrorInvalidResponse {
		t.Fatalf("Code() = %q, want %q", cerr.Code(), client.ErrorInvalidResponse)
	}
	const want = "no matching issuer key for authorization response"
	if cerr.PublicDescription() != want {
		t.Fatalf("PublicDescription() = %q, want %q", cerr.PublicDescription(), want)
	}
}

func TestCompleteAuthorizationDenied(t *testing.T) {
	c, as, _ := newTestClient(t, false)
	ctx := context.Background()

	session, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid"}})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}

	rawQuery := as.callbackFor(t, session.Handle().String(), "", "access_denied")
	result, err := c.CompleteAuthorization(ctx, client.AuthorizationCallback{RawQuery: rawQuery})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	denied, ok := result.(client.CompletionDenied)
	if !ok {
		t.Fatalf("result type = %T, want client.CompletionDenied", result)
	}
	if denied.Code != "access_denied" {
		t.Errorf("Code = %q, want access_denied", denied.Code)
	}
}

func TestHandleAuthorizationResponseRejectsReplayedState(t *testing.T) {
	c, as, _ := newTestClient(t, false)
	ctx := context.Background()

	session, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid"}})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	rawQuery := as.callbackFor(t, session.Handle().String(), "auth-code-789", "")

	if _, err := c.HandleAuthorizationResponse(ctx, client.AuthorizationCallback{RawQuery: rawQuery}); err != nil {
		t.Fatalf("first HandleAuthorizationResponse: %v", err)
	}
	if _, err := c.HandleAuthorizationResponse(ctx, client.AuthorizationCallback{RawQuery: rawQuery}); err == nil {
		t.Fatalf("second HandleAuthorizationResponse (replay) = nil error, want error")
	}
}

func TestHandleAuthorizationResponseRejectsResponseModeDowngrade(t *testing.T) {
	// Client configured for message signing, but callback arrives as a
	// plain query response — must be rejected, not silently accepted.
	c, _, _ := newTestClient(t, true)
	ctx := context.Background()

	session, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid"}})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}

	q := url.Values{}
	q.Set("state", session.Handle().String())
	q.Set("code", "downgrade-attempt")
	q.Set("iss", testIssuer)

	if _, err := c.HandleAuthorizationResponse(ctx, client.AuthorizationCallback{RawQuery: q.Encode()}); err == nil {
		t.Fatalf("HandleAuthorizationResponse(plain callback under message-signing profile) = nil error, want error")
	}
}

// RFC 9207 §2.4: a present "iss" must equal this client's configured
// issuer exactly; a mismatch must be rejected regardless of
// RequireAuthorizationResponseIss (that setting only governs what
// happens when "iss" is absent, not when it's present and wrong).
func TestHandleAuthorizationResponseRejectsIssMismatch(t *testing.T) {
	c, _, _ := newTestClient(t, false)
	ctx := context.Background()

	session, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid"}})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}

	q := url.Values{}
	q.Set("state", session.Handle().String())
	q.Set("code", "auth-code-iss-mismatch")
	q.Set("iss", "https://attacker.example")

	if _, err := c.HandleAuthorizationResponse(ctx, client.AuthorizationCallback{RawQuery: q.Encode()}); err == nil {
		t.Fatalf("HandleAuthorizationResponse(wrong iss) = nil error, want error")
	}
}

// RFC 9207 §2.4: "Clients MUST reject authorization responses without
// the iss parameter from authorization servers that do support the
// parameter" - this client can't know that on its own, so it's gated on
// Config.RequireAuthorizationResponseIss.
func TestHandleAuthorizationResponseRejectsMissingIssWhenRequired(t *testing.T) {
	as := newFakeAS(t, testIssuer, false)
	ts := httptest.NewServer(as.handler())
	t.Cleanup(ts.Close)

	cfg := validConfig(t)
	cfg.RequireAuthorizationResponseIss = true
	parURL, err := fapi.ParseEndpointURL(ts.URL+"/par", fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseEndpointURL(par): %v", err)
	}
	cfg.Endpoints.PushedAuthorizationRequest = parURL

	deps := validDependencies(t)
	deps.HTTP = ts.Client()

	c, err := client.New(cfg, deps)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}

	ctx := context.Background()
	session, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid"}})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}

	q := url.Values{}
	q.Set("state", session.Handle().String())
	q.Set("code", "auth-code-no-iss")
	// deliberately no "iss"

	if _, err := c.HandleAuthorizationResponse(ctx, client.AuthorizationCallback{RawQuery: q.Encode()}); err == nil {
		t.Fatalf("HandleAuthorizationResponse(missing iss, required) = nil error, want error")
	}
}

func TestBeginAuthorizationRejectsPARError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"error": "invalid_client"})
	}))
	defer ts.Close()

	cfg := validConfig(t)
	parURL, err := fapi.ParseEndpointURL(ts.URL+"/par", fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseEndpointURL(par): %v", err)
	}
	cfg.Endpoints.PushedAuthorizationRequest = parURL

	deps := validDependencies(t)
	deps.HTTP = ts.Client()

	c, err := client.New(cfg, deps)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	if _, err := c.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{Scope: []string{"openid"}}); err == nil {
		t.Fatalf("BeginAuthorization(PAR error) = nil error, want error")
	}
}

// failingReader always fails, simulating an exhausted or broken entropy
// source.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, fmt.Errorf("failingReader: entropy source unavailable")
}

// trackingHTTPClient records whether Do was ever called, without
// performing any real I/O.
type trackingHTTPClient struct{ called bool }

func (c *trackingHTTPClient) Do(*http.Request) (*http.Response, error) {
	c.called = true
	return nil, fmt.Errorf("trackingHTTPClient: unexpectedly called")
}

// TestBeginAuthorizationPropagatesRandomFailure proves BeginAuthorization
// fails closed — returning a client.Error rather than proceeding with
// weak or partial randomness, or reaching the network at all — when
// Dependencies.Random is broken. Asserting the HTTP client was never
// called (rather than just that some error came back) is what makes
// this pinned to the state/nonce/PKCE-verifier generation failing, not
// some later, incidental failure.
func TestBeginAuthorizationPropagatesRandomFailure(t *testing.T) {
	deps := validDependencies(t)
	deps.Random = failingReader{}
	tracker := &trackingHTTPClient{}
	deps.HTTP = tracker

	c, err := client.New(validConfig(t), deps)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	_, err = c.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{Scope: []string{"openid"}})
	if err == nil {
		t.Fatalf("BeginAuthorization(failing random) = nil error, want error")
	}
	cerr, ok := err.(*client.Error)
	if !ok {
		t.Fatalf("error type = %T, want *client.Error", err)
	}
	if cerr.Code() != client.ErrorInternal {
		t.Fatalf("Code() = %q, want %q", cerr.Code(), client.ErrorInternal)
	}
	if tracker.called {
		t.Fatalf("BeginAuthorization(failing random) made an HTTP call, want fail-closed before any I/O")
	}
}

package fapitest

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/internal/rendertest"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// This file runs real flows through the harness, over HTTP, and renders
// the results and requests each side produced, with the values the flow
// carried on the wire as the secrets no rendering may print: codes, PKCE
// verifiers, nonces, handles, request_uris, auth_req_ids, notification
// tokens, client assertions, DPoP proofs and tokens. The authorization
// code flows render the client's AuthorizationSession,
// AuthorizationCallback, CallbackSuccess, TokenSets, ResourceClients and
// ClientCredentialsTokenResult; the server's PushAuthorizationRequest
// and PushAuthorizationResult, BeginAuthorizationRequest,
// InteractionRequired, CompleteAuthorizationRequest,
// AuthorizationRedirect, the TokenEndpointRequest its token endpoint
// read and the typed request it gave, and TokenResult; and the resource
// server's VerifyRequest and ResolveAccessTokenRequest. The CIBA flow,
// with ping delivery, renders the client's session and its pending
// poll, the server's backchannel authentication request, action, inbox
// entry and completion, both notifications, the token requests and the
// results. Revocation, UserInfo and AuthorizationContext are left to
// their packages' tests and to the guard. The exceptions are the
// residuals the types document: a handle's String is its wire value,
// IDTokenClaims holds the validated nonce, and the exported fields of
// an input type (a form, an Authorization header, a callback query, a
// request_uri) hold their raw values, which fmt's reflection fallback
// and the encoders print as they print any exported field.

// exportedResidual accepts what an input type's own exported fields
// print, by design.
var exportedResidual = rendertest.Allow(rendertest.Fallback, rendertest.Encoding)

// capturedRequest is one request a client sent.
type capturedRequest struct {
	url    string
	header http.Header
	body   string
}

// captureClient is a fapihttp.HTTPClient that records every request a
// client sends, as sent, before passing it on.
type captureClient struct {
	inner fapihttp.HTTPClient
	mu    sync.Mutex
	reqs  []capturedRequest
}

func (c *captureClient) Do(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		b, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		_ = req.Body.Close()
		body = b
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	}
	c.mu.Lock()
	c.reqs = append(c.reqs, capturedRequest{url: req.URL.String(), header: req.Header.Clone(), body: string(body)})
	c.mu.Unlock()
	return c.inner.Do(req)
}

// last is the most recent request the client sent to path.
func (c *captureClient) last(t *testing.T, path string) capturedRequest {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := len(c.reqs) - 1; i >= 0; i-- {
		if u, err := url.Parse(c.reqs[i].url); err == nil && u.Path == path {
			return c.reqs[i]
		}
	}
	t.Fatalf("no request to %s was sent", path)
	return capturedRequest{}
}

// form is r's body as a form.
func (r capturedRequest) form(t *testing.T) url.Values {
	t.Helper()
	v, err := url.ParseQuery(r.body)
	if err != nil {
		t.Fatalf("parse form %q: %v", r.body, err)
	}
	return v
}

// recording is what an embedder's endpoint kept of each request it
// served, where an embedder would log it.
type recording[T any] struct {
	mu   sync.Mutex
	seen []T
}

func (r *recording[T]) add(v T) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen = append(r.seen, v)
}

// last is what the endpoint kept of the last request it served.
func (r *recording[T]) last(t *testing.T) T {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.seen) == 0 {
		t.Fatal("the endpoint served nothing")
	}
	return r.seen[len(r.seen)-1]
}

// issuance is what an embedder's token endpoint saw for one token
// request: the request it read, the typed request it built from it, and
// the TokenResult it wrote.
type issuance struct {
	read    server.TokenEndpointRequest
	request any
	result  server.TokenResult
}

// recordingTokenEndpoint is the harness's token endpoint as an embedder
// writes one, keeping the requests it built and the TokenResult the
// server returned.
type recordingTokenEndpoint struct {
	a      *authServer
	issued recording[issuance]
}

func (e *recordingTokenEndpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	req, err := server.TokenEndpointRequestFromHTTP(r)
	if err != nil {
		e.a.writeServerError(w, err)
		return
	}
	var (
		request any
		result  server.TokenResult
	)
	switch req.GrantType() {
	case "authorization_code":
		request = req.AuthorizationCodeExchange()
		result, err = e.a.srv.ExchangeAuthorizationCode(r.Context(), req.AuthorizationCodeExchange())
	case "refresh_token":
		request = req.RefreshToken()
		result, err = e.a.srv.RefreshAccessToken(r.Context(), req.RefreshToken())
	default:
		request = req.ClientCredentials()
		result, err = e.a.srv.RequestClientCredentialsToken(r.Context(), req.ClientCredentials())
	}
	if err != nil {
		e.a.writeServerError(w, err)
		return
	}
	e.issued.add(issuance{read: req, request: request, result: result})
	result.WriteJSON(w)
}

// pushed is what an embedder's PAR endpoint saw for one pushed request:
// the request it built, and the result it wrote.
type pushed struct {
	request server.PushAuthorizationRequest
	result  server.PushAuthorizationResult
}

// recordingPAREndpoint is the harness's PAR endpoint as an embedder
// writes one, reading the request as the harness does, and keeping it
// and the server's result.
type recordingPAREndpoint struct {
	a      *authServer
	pushes recording[pushed]
}

func (e *recordingPAREndpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	form, err := server.FormRequestFromHTTP(r)
	if err != nil {
		e.a.writeServerError(w, err)
		return
	}
	req := server.PushAuthorizationRequest{HTTP: form, PeerCertificate: server.PeerCertificateFromHTTP(r)}
	result, err := e.a.srv.PushAuthorizationRequest(r.Context(), req)
	if err != nil {
		e.a.writeServerError(w, err)
		return
	}
	e.pushes.add(pushed{request: req, result: result})
	result.WriteJSON(w)
}

// codeFlow is the harness h with its PAR and token endpoints recording,
// and a client over a capturing HTTP client.
type codeFlow struct {
	h        *Harness
	c        *client.Client
	capture  *captureClient
	par      *recordingPAREndpoint
	endpoint *recordingTokenEndpoint
}

func newCodeFlow(t *testing.T, cfg Config) *codeFlow {
	t.Helper()
	h := New(t, cfg)
	par := &recordingPAREndpoint{a: h.authServer}
	endpoint := &recordingTokenEndpoint{a: h.authServer}
	harnessMux := h.authServer.ts.Config.Handler
	h.authServer.ts.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/par":
			par.ServeHTTP(w, r)
		case "/token":
			endpoint.ServeHTTP(w, r)
		default:
			harnessMux.ServeHTTP(w, r)
		}
	})
	capture := &captureClient{inner: h.httpClient}
	deps := h.clientDeps
	deps.HTTP = capture
	c, err := client.New(h.clientConfig, deps)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	return &codeFlow{h: h, c: c, capture: capture, par: par, endpoint: endpoint}
}

// TestNoWireValuePrintsAfterAuthorizationCodeFlows runs the
// authorization code flow, a refresh and (under DPoP) a client
// credentials grant, under DPoP with private_key_jwt, mTLS and JARM, and
// renders each result and request with the values on the wire.
func TestNoWireValuePrintsAfterAuthorizationCodeFlows(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
	}{
		{"dpop and private_key_jwt", Config{Profile: server.ProfileFAPISecurity, ClientCredentialsGrant: true}},
		{"mtls", Config{Profile: server.ProfileFAPISecurity, SenderConstrain: storage.SenderConstrainMTLS, ClientAuthMethod: storage.ClientAuthMethodSelfSignedTLSClientAuth}},
		{"jarm", Config{Profile: server.ProfileFAPISecurityWithMessageSigning}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newCodeFlow(t, tc.cfg)
			tokens := f.authorizeAndExchange(t)
			f.checkResourceRequests(t, tokens)
			f.checkRefresh(t, tokens)
			if tc.cfg.ClientCredentialsGrant {
				f.checkClientCredentials(t)
			}
			f.checkReplayRefused(t, tokens)
		})
	}
}

// authorizeAndExchange runs the flow up to the tokens, checking each
// result's renderings on the way.
func (f *codeFlow) authorizeAndExchange(t *testing.T) client.TokenSet {
	t.Helper()
	ctx := context.Background()
	session, err := f.c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid", "accounts", "offline_access"}})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	sessionHandle := session.Handle().String()
	requestURI := f.checkPushed(t)
	rendertest.Check(t, session, []string{sessionHandle, requestURI}, rendertest.Quick())

	authorizationURL := session.URL().URL()
	query := authorizationURL.Query()
	begin := server.BeginAuthorizationRequest{RequestURI: query.Get("request_uri"), ClientID: fapi.ClientID(query.Get("client_id"))}
	rendertest.Check(t, begin, []string{requestURI}, rendertest.Quick(), exportedResidual)
	action, err := f.h.authServer.srv.BeginAuthorization(ctx, begin)
	if err != nil {
		t.Fatalf("server BeginAuthorization: %v", err)
	}
	required, ok := action.(server.InteractionRequired)
	if !ok {
		t.Fatalf("BeginAuthorization = %T, want InteractionRequired", action)
	}
	rendertest.Check(t, required, []string{required.Handle.String()}, rendertest.Quick())

	redirect := f.complete(t, required)
	destination := redirect.Destination().URL()
	cb := client.AuthorizationCallback{RawQuery: destination.RawQuery, Session: session.Handle()}
	rendertest.Check(t, cb, []string{sessionHandle}, rendertest.Quick())
	result, err := f.c.HandleAuthorizationResponse(ctx, cb)
	if err != nil {
		t.Fatalf("HandleAuthorizationResponse: %v", err)
	}
	success, ok := result.(client.CallbackSuccess)
	if !ok {
		t.Fatalf("HandleAuthorizationResponse = %T, want CallbackSuccess", result)
	}
	tokens, err := f.c.ExchangeCode(ctx, success.Response)
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}

	tokenForm := f.capture.last(t, "/token").form(t)
	code, verifier := tokenForm.Get("code"), tokenForm.Get("code_verifier")
	rendertest.Check(t, redirect, []string{redirectCredential(destination)}, rendertest.Quick())
	rendertest.Check(t, cb, []string{code}, rendertest.Quick(), exportedResidual)
	rendertest.Check(t, success, []string{code, verifier, tokens.IDTokenClaims.Nonce}, rendertest.Quick())
	f.checkIssuance(t, append([]string{code, verifier}, wireCredentials(f.capture.last(t, "/token"))...))
	checkTokenSet(t, tokens)
	return tokens
}

// complete authorizes required's interaction as the harness's end user.
func (f *codeFlow) complete(t *testing.T, required server.InteractionRequired) server.AuthorizationRedirect {
	t.Helper()
	subjectID, _ := server.NewSubjectID(Subject)
	subject, _ := server.NewAuthenticatedSubject(subjectID)
	auth, _ := server.NewAuthenticationContext(f.h.Clock.Now(), "urn:mace:incommon:iap:silver", []string{"pwd"})
	complete := server.CompleteAuthorizationRequest{
		Handle: required.Handle,
		Result: server.Authorize(subject, auth, server.GrantedAuthorization{Scope: required.Interaction.Scope}),
	}
	rendertest.Check(t, complete, []string{required.Handle.String()}, rendertest.Quick())
	result, err := f.h.authServer.srv.CompleteAuthorization(context.Background(), complete)
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	redirect, ok := result.(server.AuthorizationRedirect)
	if !ok {
		t.Fatalf("CompleteAuthorization = %T, want AuthorizationRedirect", result)
	}
	return redirect
}

// checkPushed checks the pushed authorization request the PAR endpoint
// read last, whose form carries the client's assertion, request object,
// state and nonce (its exported fields hold them raw, by design), and
// the result it wrote, whose request_uri it returns.
func (f *codeFlow) checkPushed(t *testing.T) string {
	t.Helper()
	pushed := f.par.pushes.last(t)
	form := f.capture.last(t, "/par").form(t)
	rendertest.Check(t, pushed.request, nonEmpty(form.Get("client_assertion"), form.Get("request"), form.Get("state"), form.Get("nonce")), rendertest.Quick(), exportedResidual)
	requestURI := pushed.result.RequestURI.String()
	rendertest.Check(t, pushed.result, []string{requestURI}, rendertest.Quick())
	return requestURI
}

// redirectCredential is what a redirect's query carries that completes
// the flow: the code, or a JARM response carrying it.
func redirectCredential(destination url.URL) string {
	if response := destination.Query().Get("response"); response != "" {
		return response
	}
	return destination.Query().Get("code")
}

// wireCredentials is the client authentication and DPoP proof r
// carried, if any.
func wireCredentials(r capturedRequest) []string {
	var out []string
	if values, err := url.ParseQuery(r.body); err == nil && values.Get("client_assertion") != "" {
		out = append(out, values.Get("client_assertion"))
	}
	if proof := r.header.Get("DPoP"); proof != "" {
		out = append(out, proof)
	}
	return out
}

// checkIssuance checks the token endpoint's last request, as it read it,
// which prints no credential in any position, and as the typed request
// it gave, whose exported fields hold them raw, by design; and the
// TokenResult it returned, which holds tokens.
func (f *codeFlow) checkIssuance(t *testing.T, credentials []string) {
	t.Helper()
	issued := f.endpoint.issued.last(t)
	rendertest.Check(t, issued.read, credentials, rendertest.Quick())
	switch request := issued.request.(type) {
	case server.AuthorizationCodeExchangeRequest:
		rendertest.Check(t, request, credentials, rendertest.Quick(), exportedResidual)
	case server.RefreshTokenRequest:
		rendertest.Check(t, request, credentials, rendertest.Quick(), exportedResidual)
	case server.ClientCredentialsTokenRequest:
		rendertest.Check(t, request, credentials, rendertest.Quick(), exportedResidual)
	}
	rendertest.Check(t, issued.result, nonEmpty(issued.result.AccessToken.Reveal(), issued.result.IDToken.Reveal(), issued.result.RefreshToken.Reveal()), rendertest.Quick())
}

// checkTokenSet checks tokens' renderings show none of its tokens.
func checkTokenSet(t *testing.T, tokens client.TokenSet) {
	t.Helper()
	rendertest.Check(t, tokens, nonEmpty(tokens.AccessToken.Reveal(), tokens.IDToken.Reveal(), tokens.RefreshToken.Reveal()), rendertest.Quick())
}

func nonEmpty(values ...string) []string {
	var out []string
	for _, v := range values {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// checkResourceRequests checks a ResourceClient for tokens, and the
// requests the resource server builds from what it sends.
func (f *codeFlow) checkResourceRequests(t *testing.T, tokens client.TokenSet) {
	t.Helper()
	accessToken := []string{tokens.AccessToken.Reveal()}
	rc := f.c.ProtectedResource(tokens)
	rendertest.Check(t, rc, accessToken, rendertest.Quick())
	f.fetchUserInfo(t, rc)
	sent := f.capture.last(t, "/userinfo")
	req, err := http.NewRequest(http.MethodGet, sent.url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header = sent.header.Clone()
	rendertest.Check(t, resource.VerifyRequestFromHTTP(req), append(accessToken, wireCredentials(sent)...), rendertest.Quick(), exportedResidual)
	rendertest.Check(t, resource.ResolveAccessTokenRequest{Raw: accessToken[0], Now: f.h.Clock.Now()}, accessToken, rendertest.Quick(), exportedResidual)
}

// fetchUserInfo has rc call the harness's UserInfo endpoint, failing t
// unless it answers 200.
func (f *codeFlow) fetchUserInfo(t *testing.T, rc *client.ResourceClient) {
	t.Helper()
	userinfo := f.h.clientConfig.Endpoints.UserInfo.URL()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, userinfo.String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := rc.Do(context.Background(), req)
	if err != nil {
		t.Fatalf("ResourceClient.Do: %v", err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("UserInfo answered %d, want 200", res.StatusCode)
	}
}

// checkRefresh refreshes tokens and checks the request the token
// endpoint built, its TokenResult and the refreshed set.
func (f *codeFlow) checkRefresh(t *testing.T, tokens client.TokenSet) {
	t.Helper()
	refreshed, err := f.c.RefreshTokens(context.Background(), client.RefreshTokenRequest{Tokens: tokens})
	if err != nil {
		t.Fatalf("RefreshTokens: %v", err)
	}
	sent := f.capture.last(t, "/token")
	f.checkIssuance(t, append([]string{tokens.RefreshToken.Reveal()}, wireCredentials(sent)...))
	checkTokenSet(t, refreshed)
}

// checkClientCredentials runs the client credentials grant and checks
// its result, its ResourceClient and what the token endpoint saw.
func (f *codeFlow) checkClientCredentials(t *testing.T) {
	t.Helper()
	cc, err := f.c.RequestClientCredentialsToken(context.Background(), client.ClientCredentialsTokenRequest{Scope: []string{"accounts"}})
	if err != nil {
		t.Fatalf("RequestClientCredentialsToken: %v", err)
	}
	accessToken := []string{cc.AccessToken.Reveal()}
	rendertest.Check(t, cc, accessToken, rendertest.Quick())
	rendertest.Check(t, f.c.ClientCredentialsResource(cc), accessToken, rendertest.Quick())
	f.checkIssuance(t, wireCredentials(f.capture.last(t, "/token")))
}

// checkReplayRefused replays the flow's code and verifier at the token
// endpoint without the client's credentials, as a reader of an old log
// line could have, and checks it is refused and the honest token still
// works.
func (f *codeFlow) checkReplayRefused(t *testing.T, tokens client.TokenSet) {
	t.Helper()
	var tokenForm url.Values
	for i := len(f.capture.reqs) - 1; i >= 0; i-- {
		if form, err := url.ParseQuery(f.capture.reqs[i].body); err == nil && form.Get("grant_type") == "authorization_code" {
			tokenForm = form
			break
		}
	}
	replay := url.Values{
		"grant_type": {"authorization_code"}, "code": {tokenForm.Get("code")}, "code_verifier": {tokenForm.Get("code_verifier")},
		"redirect_uri": {tokenForm.Get("redirect_uri")}, "client_id": {ClientID.String()},
	}
	tokenURL := f.h.serverConfig.Endpoints.Token.URL()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, tokenURL.String(), strings.NewReader(replay.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// The harness's own transport presents the client's certificate: a
	// log reader has none.
	transport := f.h.authServer.ts.Client().Transport.(*http.Transport).Clone()
	if transport.TLSClientConfig != nil {
		transport.TLSClientConfig.Certificates = nil
	}
	res, err := (&http.Client{Transport: transport}).Do(req)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	var body map[string]any
	_ = json.NewDecoder(res.Body).Decode(&body)
	_ = res.Body.Close()
	if res.StatusCode == http.StatusOK {
		t.Errorf("a code replayed without the client's credentials was redeemed: %v", body)
	}
	f.fetchUserInfo(t, f.c.ProtectedResource(tokens))
}

// lockedClock is a manual clock the CIBA flow's servers and client
// share, safe to read from their handlers.
type lockedClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *lockedClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *lockedClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// cibaClientKeys resolves the CIBA client's verification keys from its
// key manager.
type cibaClientKeys struct{ manager keys.KeyManager }

func (s cibaClientKeys) ResolveVerificationKeys(ctx context.Context, req keys.ClientKeyRequest) (keys.VerificationKeySet, error) {
	purpose := map[keys.VerificationPurpose]keys.SigningPurpose{
		keys.ClientAssertionVerification:                  keys.ClientAuthentication,
		keys.BackchannelAuthenticationRequestVerification: keys.BackchannelAuthenticationRequestSigning,
	}[req.Purpose]
	if req.ClientID != ClientID || purpose == 0 {
		return keys.VerificationKeySet{}, fmt.Errorf("fapitest: no %v key for %q", req.Purpose, req.ClientID)
	}
	info, err := s.manager.PublicKey(ctx, purpose, req.Algorithm)
	if err != nil {
		return keys.VerificationKeySet{}, err
	}
	return keys.VerificationKeySet{Keys: []keys.VerificationKey{{KeyID: info.KeyID, Algorithm: req.Algorithm, PublicKey: info.PublicKey}}}, nil
}

// cibaSubjects resolves the harness's end user from a login_hint.
type cibaSubjects struct{}

func (cibaSubjects) ResolveBackchannelSubject(_ context.Context, _ fapi.ClientID, hints server.BackchannelAuthenticationHints) (server.SubjectID, error) {
	if string(hints.LoginHint) != Subject {
		return server.SubjectID{}, server.ErrUnknownUserID
	}
	return server.NewSubjectID(Subject)
}

// cibaFlow is an authorization server with CIBA ping delivery and a
// relying party with its notification endpoint, over HTTP, recording
// what both sides saw.
type cibaFlow struct {
	clock   *lockedClock
	srv     *server.Server
	c       *client.Client
	capture *captureClient
	rp      *httptest.Server

	mu       sync.Mutex
	session  client.BackchannelAuthenticationSession
	begun    []any // the server's inbound requests and actions
	notes    []client.BackchannelNotification
	verdicts []bool
	notices  []server.BackchannelNotification
}

// Notify sends note as the server's notifier would, recording it.
func (f *cibaFlow) Notify(ctx context.Context, note server.BackchannelNotification) error {
	f.mu.Lock()
	f.notices = append(f.notices, note)
	f.mu.Unlock()
	req, err := server.NewBackchannelNotificationRequest(ctx, note)
	if err != nil {
		return err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	return res.Body.Close()
}

func (f *cibaFlow) record(v any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.begun = append(f.begun, v)
}

// notify is the relying party's notification endpoint.
func (f *cibaFlow) notify(w http.ResponseWriter, r *http.Request) {
	n, err := client.ParseBackchannelNotification(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	ok := n.Authenticates(f.session)
	f.notes, f.verdicts = append(f.notes, n), append(f.verdicts, ok)
	f.mu.Unlock()
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// authorize is the authorization server's backchannel authentication
// endpoint.
func (f *cibaFlow) authorize(w http.ResponseWriter, r *http.Request) {
	req, err := server.BeginBackchannelAuthenticationRequestFromHTTP(r)
	if err != nil {
		server.WriteError(w, err)
		return
	}
	f.record(req)
	action, err := f.srv.BeginBackchannelAuthentication(r.Context(), req)
	if err != nil {
		server.WriteError(w, err)
		return
	}
	switch a := action.(type) {
	case server.BackchannelInteractionRequired:
		f.record(a)
		a.WriteJSON(w)
	case server.BackchannelAuthenticationLocalError:
		a.Error.WriteJSON(w)
	}
}

// token is the authorization server's token endpoint, for CIBA polls.
func (f *cibaFlow) token(w http.ResponseWriter, r *http.Request) {
	req, err := server.TokenEndpointRequestFromHTTP(r)
	if err != nil {
		server.WriteError(w, err)
		return
	}
	f.record(req)
	f.record(req.BackchannelTokenExchange())
	result, err := f.srv.ExchangeBackchannelAuthentication(r.Context(), req.BackchannelTokenExchange())
	if err != nil {
		server.WriteError(w, err)
		return
	}
	f.record(result)
	result.WriteJSON(w)
}

// recorded is the last of what the server saw that is a T.
func recorded[T any](t *testing.T, f *cibaFlow) T {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := len(f.begun) - 1; i >= 0; i-- {
		if v, ok := f.begun[i].(T); ok {
			return v
		}
	}
	var zero T
	t.Fatalf("the server saw no %T", zero)
	return zero
}

func newCIBAFlow(t *testing.T) *cibaFlow {
	t.Helper()
	f := &cibaFlow{clock: &lockedClock{now: time.Unix(1_800_000_000, 0)}}
	f.rp = httptest.NewServer(http.HandlerFunc(f.notify))
	t.Cleanup(f.rp.Close)
	mux := http.NewServeMux()
	mux.HandleFunc("/bc-authorize", f.authorize)
	mux.HandleFunc("/token", f.token)
	as := httptest.NewServer(mux)
	t.Cleanup(as.Close)

	asKeys := newAlgorithmKeyManager(t, fapi.ES256, keys.IDTokenSigning, keys.AccessTokenSigning)
	clientKeys := newAlgorithmKeyManager(t, fapi.ES256, keys.ClientAuthentication, keys.BackchannelAuthenticationRequestSigning, keys.DPoPProofSigning)
	issuer, endpoints := cibaEndpoints(t, as.URL)
	f.srv = newCIBAServer(t, f, issuer, endpoints, asKeys, clientKeys)
	f.c, f.capture = newCIBAClient(t, f.clock, issuer, endpoints, asKeys, clientKeys)
	return f
}

func cibaEndpoints(t *testing.T, base string) (fapi.URL, server.Endpoints) {
	t.Helper()
	issuer, err := fapi.ParseIssuerURL(Issuer)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := func(path string) fapi.URL {
		u, err := fapi.ParseEndpointURL(base+path, fapi.AllowLoopbackHTTP())
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	return issuer, server.Endpoints{
		Authorization: endpoint("/authorize"), Token: endpoint("/token"), PushedAuthorizationRequest: endpoint("/par"),
		JWKS: endpoint("/jwks"), BackchannelAuthentication: endpoint("/bc-authorize"),
	}
}

func newCIBAServer(t *testing.T, f *cibaFlow, issuer fapi.URL, endpoints server.Endpoints, asKeys, clientKeys keys.KeyManager) *server.Server {
	t.Helper()
	notifyURL, err := fapi.ParseEndpointURL(f.rp.URL+"/notify", fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatal(err)
	}
	registered, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID: ClientID, ClientAuthMethod: storage.ClientAuthMethodPrivateKeyJWT, SenderConstrain: storage.SenderConstrainDPoP,
		ClientAssertionAlgorithm: fapi.ES256, RequestObjectAlgorithm: fapi.ES256, BackchannelAuthenticationRequestAlgorithm: fapi.ES256,
		AllowedScopes: []string{"openid", "accounts"}, BackchannelTokenDeliveryMode: storage.BackchannelTokenDeliveryModePing,
		BackchannelClientNotificationEndpoint: notifyURL,
	})
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}
	limits := server.RecommendedLimits()
	limits.BackchannelAuthenticationRequestLifetime = 2 * time.Minute
	limits.MaxBackchannelAuthenticationRequestLifetime = time.Minute
	limits.BackchannelAuthenticationPollInterval = time.Second
	srv, err := server.New(server.Config{
		Subjects: server.PublicSubjects(), Issuer: issuer, Endpoints: endpoints, Profile: server.ProfileFAPISecurity,
		Algorithms: server.AlgorithmPolicy{
			ClientAssertion: server.AlgorithmSet{fapi.ES256}, RequestObject: server.AlgorithmSet{fapi.ES256},
			JARM: fapi.ES256, IDToken: fapi.ES256, BackchannelAuthenticationRequest: server.AlgorithmSet{fapi.ES256},
		},
		Limits: limits, Assurance: server.AssuranceDevelopment,
	}, server.Dependencies{
		Clients: &memClientRepository{client: registered}, Transactions: memstore.NewTransactionStore(),
		Grants: memstore.NewGrantStore(), Replay: memstore.NewReplayStore(), ClientKeys: cibaClientKeys{manager: clientKeys},
		Keys: asKeys, AccessTokens: server.JWTAccessTokens{Keys: asKeys, Algorithm: fapi.ES256},
		Revocation: memstore.NewRevocationStore(), ClientCertificateTrust: server.NoClientCertificateChainTrust{},
		Clock: f.clock, Random: rand.Reader, Backchannel: memstore.NewBackchannelAuthenticationStore(),
		BackchannelNotifier: f, BackchannelSubjects: cibaSubjects{}, BackchannelInbox: memstore.NewBackchannelInbox(),
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return srv
}

func newCIBAClient(t *testing.T, clock *lockedClock, issuer fapi.URL, endpoints server.Endpoints, asKeys, clientKeys keys.KeyManager) (*client.Client, *captureClient) {
	t.Helper()
	issuerKeys, err := keys.NewLocalIssuerKeys(issuer, asKeys)
	if err != nil {
		t.Fatal(err)
	}
	capture := &captureClient{inner: &http.Client{}}
	limits := client.RecommendedLimits()
	limits.BackchannelAuthenticationRequestLifetime = time.Minute
	c, err := client.New(client.Config{
		Issuer: issuer, ClientID: ClientID, Profile: client.ProfileFAPISecurity, Assurance: client.AssuranceDevelopment,
		AuthorizationResponseIssPolicy: client.TolerateAbsentAuthorizationResponseIss,
		Endpoints:                      client.Endpoints{Token: endpoints.Token, BackchannelAuthentication: endpoints.BackchannelAuthentication},
		Algorithms:                     client.Algorithms{ClientAuthentication: fapi.ES256, DPoP: fapi.ES256, IDToken: fapi.ES256, BackchannelAuthenticationRequest: fapi.ES256},
		Limits:                         limits, SenderConstrain: storage.SenderConstrainDPoP, ClientAuthMethod: storage.ClientAuthMethodPrivateKeyJWT,
		BackchannelTokenDeliveryMode: storage.BackchannelTokenDeliveryModePing,
	}, client.Dependencies{Keys: clientKeys, IssuerKeys: issuerKeys, HTTP: capture, Clock: clock, Random: rand.Reader})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	return c, capture
}

// TestNoWireValuePrintsAfterCIBAPingFlow runs a CIBA flow with ping
// delivery and renders what both sides saw at each step: the client's
// session and its pending poll, the server's backchannel authentication
// request, action, inbox entry and completion, both pings, the token
// requests and the token result, and the approved tokens.
func TestNoWireValuePrintsAfterCIBAPingFlow(t *testing.T) {
	ctx := context.Background()
	f := newCIBAFlow(t)
	session, err := f.c.BeginBackchannelAuthentication(ctx, client.BeginBackchannelAuthenticationRequest{Scope: []string{"openid", "accounts"}, LoginHint: Subject, BindingMessage: "W4SCT"})
	if err != nil {
		t.Fatalf("BeginBackchannelAuthentication: %v", err)
	}
	f.mu.Lock()
	f.session = session
	f.mu.Unlock()
	sessionValues := []string{session.AuthReqID(), session.NotificationToken()}
	rendertest.Check(t, session, sessionValues, rendertest.Quick())

	begin := f.capture.last(t, "/bc-authorize")
	rendertest.Check(t, recorded[server.BeginBackchannelAuthenticationRequest](t, f), append([]string{begin.form(t).Get("request")}, wireCredentials(begin)...), rendertest.Quick(), exportedResidual)
	action := recorded[server.BackchannelInteractionRequired](t, f)
	rendertest.Check(t, action, []string{action.AuthReqID.String(), action.Handle.String()}, rendertest.Quick())

	result, err := f.c.PollBackchannelAuthentication(ctx, session)
	if err != nil {
		t.Fatalf("PollBackchannelAuthentication: %v", err)
	}
	pending, ok := result.(client.BackchannelAuthenticationPending)
	if !ok {
		t.Fatalf("poll = %T, want Pending", result)
	}
	rendertest.Check(t, pending, sessionValues, rendertest.Quick())
	f.checkInboxAndDecide(t, action)
	f.checkPings(t, sessionValues)
	f.checkApproval(t, pending.Session)
}

// checkInboxAndDecide lists the user's pending request, checks it, and
// approves it, which sends the ping.
func (f *cibaFlow) checkInboxAndDecide(t *testing.T, action server.BackchannelInteractionRequired) {
	t.Helper()
	ctx := context.Background()
	subjectID, _ := server.NewSubjectID(Subject)
	inbox, err := f.srv.ListBackchannelInteractions(ctx, subjectID)
	if err != nil || len(inbox) != 1 || inbox[0].Handle != action.Handle {
		t.Fatalf("ListBackchannelInteractions = %d entries, %v; want the request just made", len(inbox), err)
	}
	rendertest.Check(t, inbox[0], []string{action.Handle.String()}, rendertest.Quick())
	subject, _ := server.NewAuthenticatedSubject(subjectID)
	auth, _ := server.NewAuthenticationContext(f.clock.Now(), "urn:mace:incommon:iap:silver", []string{"pwd"})
	complete := server.CompleteBackchannelAuthenticationRequest{Handle: inbox[0].Handle, Result: server.Authorize(subject, auth, server.GrantedAuthorization{Scope: inbox[0].Interaction.Scope})}
	rendertest.Check(t, complete, []string{action.Handle.String()}, rendertest.Quick())
	if err := f.srv.CompleteBackchannelAuthentication(ctx, complete); err != nil {
		t.Fatalf("CompleteBackchannelAuthentication: %v", err)
	}
}

// checkPings checks the notification the server sent and the one the
// relying party received, which authenticated.
func (f *cibaFlow) checkPings(t *testing.T, sessionValues []string) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.notices) != 1 || len(f.notes) != 1 || !f.verdicts[0] {
		t.Fatalf("%d notifications sent, %d received (authenticated: %v); want one, authenticated", len(f.notices), len(f.notes), f.verdicts)
	}
	rendertest.Check(t, f.notes[0], sessionValues, rendertest.Quick())
	rendertest.Check(t, f.notices[0], sessionValues[1:], rendertest.Quick())
	// The notification's AuthReqID is an exported string: fmt's
	// reflection fallback prints it, as any exported field.
	rendertest.Check(t, f.notices[0], sessionValues[:1], rendertest.Quick(), rendertest.Allow(rendertest.Fallback))
}

// checkApproval polls for the decision, once the interval has passed,
// and checks the token request the server saw, its TokenResult and the
// approved tokens; then has someone without the client's credentials
// poll with the auth_req_id, which is refused.
func (f *cibaFlow) checkApproval(t *testing.T, session client.BackchannelAuthenticationSession) {
	t.Helper()
	ctx := context.Background()
	f.clock.Advance(session.Interval() + time.Second)
	result, err := f.c.PollBackchannelAuthentication(ctx, session)
	if err != nil {
		t.Fatalf("PollBackchannelAuthentication: %v", err)
	}
	approved, ok := result.(client.BackchannelAuthenticationApproved)
	if !ok {
		t.Fatalf("poll = %T, want Approved", result)
	}
	tokens := nonEmpty(approved.Tokens.AccessToken.Reveal(), approved.Tokens.IDToken.Reveal(), approved.Tokens.RefreshToken.Reveal())
	rendertest.Check(t, approved, tokens, rendertest.Quick())
	poll := f.capture.last(t, "/token")
	pollValues := append([]string{session.AuthReqID()}, wireCredentials(poll)...)
	rendertest.Check(t, recorded[server.TokenEndpointRequest](t, f), pollValues, rendertest.Quick())
	rendertest.Check(t, recorded[server.BackchannelTokenExchangeRequest](t, f), pollValues, rendertest.Quick(), exportedResidual)
	rendertest.Check(t, recorded[server.TokenResult](t, f), tokens, rendertest.Quick())

	form := url.Values{"grant_type": {server.CIBAGrantType}, "auth_req_id": {session.AuthReqID()}, "client_id": {ClientID.String()}}
	res, err := http.Post(poll.url, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("poll without credentials: %v", err)
	}
	_ = res.Body.Close()
	if res.StatusCode == http.StatusOK {
		t.Error("a poll with the auth_req_id and without the client's credentials was answered with tokens")
	}
}

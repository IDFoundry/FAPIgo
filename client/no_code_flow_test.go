package client_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/client/sessioncookie"
	"github.com/idfoundry/fapigo/storage"
)

// noCodeFlowDescription is the description of the error a client
// without the authorization code flow refuses that flow with.
const noCodeFlowDescription = "the authorization code flow is not configured: it needs endpoints.authorization and sessions"

// noCodeFlowConfig is validConfig and validDependencies, under
// AssuranceProduction when production, for a client with no
// authorization code flow: no authorization or pushed authorization
// request endpoint, no redirect URI and no session store.
func noCodeFlowConfig(t *testing.T, production bool) (client.Config, client.Dependencies) {
	t.Helper()
	cfg := validConfig(t)
	cfg.Endpoints.Authorization, cfg.Endpoints.PushedAuthorizationRequest, cfg.RedirectURI = fapi.URL{}, fapi.URL{}, ""
	deps := validDependencies(t)
	if production {
		asProduction(&cfg)
		cfg.AuthorizationResponseIssPolicy = client.RequireAuthorizationResponseIss
		deps = productionDeps(t)
	}
	deps.Sessions = nil
	return cfg, deps
}

// newClientCredentialsOnlyClient is a client for client credentials
// only, returned with its issuer.
func newClientCredentialsOnlyClient(t *testing.T, production bool) (*client.Client, string) {
	t.Helper()
	cfg, deps := noCodeFlowConfig(t, production)
	cfg.Algorithms.IDToken = 0
	c, err := client.New(cfg, deps)
	if err != nil {
		t.Fatalf("New(client credentials only): %v", err)
	}
	return c, testIssuer
}

// newCIBAOnlyClient is a client for CIBA only, returned with its issuer.
func newCIBAOnlyClient(t *testing.T, production bool) (*client.Client, string) {
	t.Helper()
	cfg, deps := noCodeFlowConfig(t, production)
	cfg.Endpoints.BackchannelAuthentication = mustParseEndpointURL(t, testIssuer+"/backchannel-authenticate")
	cfg.Algorithms.BackchannelAuthenticationRequest = fapi.ES256
	cfg.Limits.BackchannelAuthenticationRequestLifetime = time.Minute
	c, err := client.New(cfg, deps)
	if err != nil {
		t.Fatalf("New(CIBA only): %v", err)
	}
	return c, testIssuer
}

// newDiscoveredClientWithoutRedirect is NewFromDiscovery's client for a
// Config with no redirect URI, which discovery leaves without the
// authorization code flow's endpoints, returned with its issuer.
func newDiscoveredClientWithoutRedirect(t *testing.T, production bool) (*client.Client, string) {
	t.Helper()
	discovered := discoverForAlgorithmTests(t)
	cfg, deps := noCodeFlowConfig(t, production)
	cfg.Issuer, cfg.Endpoints = discovered.Issuer(), client.Endpoints{}
	cfg.Algorithms.IDToken = fapi.ES256
	c, err := client.NewFromDiscovery(discovered, cfg, deps)
	if err != nil {
		t.Fatalf("NewFromDiscovery(no redirect URI): %v", err)
	}
	return c, discovered.Issuer().String()
}

// noCodeFlowShapes are the ways to build a client without the
// authorization code flow.
var noCodeFlowShapes = []struct {
	name  string
	build func(t *testing.T, production bool) (*client.Client, string)
}{
	{"client credentials only", newClientCredentialsOnlyClient},
	{"CIBA only", newCIBAOnlyClient},
	{"NewFromDiscovery without a redirect URI", newDiscoveredClientWithoutRedirect},
}

// noCodeFlowCallbacks are callbacks sent to a client for issuer that has
// no authorization code flow, bound, where they carry a Session, to a
// flow begun elsewhere whose state and handle the sender holds.
func noCodeFlowCallbacks(issuer, state string, handle client.SessionHandle) map[string]client.AuthorizationCallback {
	return map[string]client.AuthorizationCallback{
		"code, state and iss":      {RawQuery: url.Values{"code": {"c"}, "state": {state}, "iss": {issuer}}.Encode(), Session: handle},
		"error, state and iss":     {RawQuery: url.Values{"error": {"access_denied"}, "state": {state}, "iss": {issuer}}.Encode(), Session: handle},
		"code and state, no iss":   {RawQuery: url.Values{"code": {"c"}, "state": {state}}.Encode(), Session: handle},
		"no Session":               {RawQuery: url.Values{"code": {"c"}, "state": {state}, "iss": {issuer}}.Encode()},
		"a JARM-shaped response":   {RawQuery: url.Values{"response": {"a.b.c"}}.Encode(), Session: handle},
		"an empty query, no state": {Session: handle},
	}
}

// callWithoutPanic returns f's error, failing t if f panics instead.
func callWithoutPanic(t *testing.T, name string, f func() error) error {
	t.Helper()
	defer func() {
		if p := recover(); p != nil {
			t.Fatalf("%s panicked: %v", name, p)
		}
	}()
	return f()
}

// assertNoCodeFlowRefusal fails t unless err is the ErrorInvalidRequest a
// client without the authorization code flow refuses it with.
func assertNoCodeFlowRefusal(t *testing.T, call string, err error) {
	t.Helper()
	var cerr *client.Error
	if !errors.As(err, &cerr) || cerr.Code() != client.ErrorInvalidRequest || cerr.PublicDescription() != noCodeFlowDescription {
		t.Errorf("%s = %v, want %s: %s", call, err, client.ErrorInvalidRequest, noCodeFlowDescription)
	}
}

// checkNoCodeFlowRefusal fails t unless c refuses cb, through
// HandleAuthorizationResponse and CompleteAuthorization alike, with the
// error of a client without the authorization code flow.
func checkNoCodeFlowRefusal(t *testing.T, name string, c *client.Client, cb client.AuthorizationCallback) {
	t.Helper()
	ctx := context.Background()
	err := callWithoutPanic(t, name, func() error { _, err := c.HandleAuthorizationResponse(ctx, cb); return err })
	assertNoCodeFlowRefusal(t, name+": HandleAuthorizationResponse", err)
	err = callWithoutPanic(t, name, func() error { _, err := c.CompleteAuthorization(ctx, cb); return err })
	assertNoCodeFlowRefusal(t, name+": CompleteAuthorization", err)
}

// TestCallbackOnAClientWithoutTheCodeFlowIsRefused covers a callback
// routed to a client that has no authorization code flow, under either
// assurance level, carrying the state and handle of a flow begun at
// another client: whatever its shape, it is refused with
// ErrorInvalidRequest, never a panic on the session store the client
// lacks.
func TestCallbackOnAClientWithoutTheCodeFlowIsRefused(t *testing.T) {
	browserFlow, as, _ := newTestClient(t, false)
	session, err := browserFlow.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{Scope: []string{"openid"}})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	for _, shape := range noCodeFlowShapes {
		for _, production := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/production=%v", shape.name, production), func(t *testing.T) {
				c, issuer := shape.build(t, production)
				for name, cb := range noCodeFlowCallbacks(issuer, as.lastState, session.Handle()) {
					checkNoCodeFlowRefusal(t, name, c, cb)
				}
			})
		}
	}
}

// TestBeginAuthorizationWithoutTheCodeFlowIsRefused covers
// BeginAuthorization on a client without the authorization code flow,
// under either assurance level: ErrorInvalidRequest, never a panic.
func TestBeginAuthorizationWithoutTheCodeFlowIsRefused(t *testing.T) {
	for _, shape := range noCodeFlowShapes {
		for _, production := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/production=%v", shape.name, production), func(t *testing.T) {
				c, _ := shape.build(t, production)
				err := callWithoutPanic(t, "BeginAuthorization", func() error {
					_, err := c.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{Scope: []string{"openid"}})
					return err
				})
				assertNoCodeFlowRefusal(t, "BeginAuthorization", err)
			})
		}
	}
}

// parAnsweringHTTP answers every request, whatever its URL, as a pushed
// authorization request endpoint would, counting them.
type parAnsweringHTTP struct{ requests int }

func (h *parAnsweringHTTP) Do(req *http.Request) (*http.Response, error) {
	h.requests++
	return &http.Response{
		StatusCode: http.StatusCreated, Header: http.Header{"Content-Type": {"application/json"}}, Request: req,
		Body: io.NopCloser(strings.NewReader(`{"request_uri":"urn:ietf:params:oauth:request_uri:x","expires_in":60}`)),
	}, nil
}

// countingSessionStore is a fakeSessionStore counting the calls made to
// it.
type countingSessionStore struct {
	*fakeSessionStore
	calls int
}

func (s *countingSessionStore) Create(ctx context.Context, session storage.NewSession) error {
	s.calls++
	return s.fakeSessionStore.Create(ctx, session)
}

func (s *countingSessionStore) Consume(ctx context.Context, c storage.SessionConsumption) (storage.ConsumedSession, error) {
	s.calls++
	return s.fakeSessionStore.Consume(ctx, c)
}

// TestBeginAuthorizationWithoutTheCodeFlowSendsNothing: BeginAuthorization
// on a client without the authorization code flow sends no request, even
// through an HTTP client that would answer one to an unset endpoint, and
// touches no session store, whether the client has one or not.
func TestBeginAuthorizationWithoutTheCodeFlowSendsNothing(t *testing.T) {
	for name, store := range map[string]*countingSessionStore{
		"no session store": nil,
		"a session store":  {fakeSessionStore: newFakeSessionStore()},
	} {
		t.Run(name, func(t *testing.T) { checkBeginSendsNothing(t, store) })
	}
}

// checkBeginSendsNothing is TestBeginAuthorizationWithoutTheCodeFlowSendsNothing
// for a client with store as its session store, or none when it's nil.
func checkBeginSendsNothing(t *testing.T, store *countingSessionStore) {
	t.Helper()
	cfg, deps := noCodeFlowConfig(t, false)
	cfg.Algorithms.IDToken = 0
	answering := &parAnsweringHTTP{}
	deps.HTTP = answering
	if store != nil {
		deps.Sessions = store
	}
	c, err := client.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = callWithoutPanic(t, "BeginAuthorization", func() error {
		_, err := c.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{Scope: []string{"openid"}})
		return err
	})
	assertNoCodeFlowRefusal(t, "BeginAuthorization", err)
	if answering.requests != 0 {
		t.Fatalf("BeginAuthorization sent %d requests, want none", answering.requests)
	}
	if store != nil && store.calls != 0 {
		t.Fatalf("BeginAuthorization made %d session store calls, want none", store.calls)
	}
}

// TestNewProductionRefusesDeviceLocalBindingWithoutTheCodeFlow covers
// CallbackBindingDeviceLocalStore on a client with no redirect URI,
// with or without a session store: it isn't a native app, so
// AssuranceProduction refuses it as it does a web client's.
func TestNewProductionRefusesDeviceLocalBindingWithoutTheCodeFlow(t *testing.T) {
	for name, sessions := range map[string]storage.SessionStore{
		"no session store": nil,
		"a session store":  assuringSessionStore{fakeSessionStore: newFakeSessionStore(), caps: storage.Capabilities{Durable: true, AtomicConsume: true}},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, deps := noCodeFlowConfig(t, true)
			cfg.Algorithms.IDToken = 0
			cfg.CallbackBinding = client.CallbackBindingDeviceLocalStore
			deps.Sessions = sessions
			if _, err := client.New(cfg, deps); err == nil || !strings.Contains(err.Error(), "CallbackBindingDeviceLocalStore") {
				t.Fatalf("New(production, device-local binding, no redirect URI) = %v, want the binding refused", err)
			}
		})
	}
}

// TestDeviceLocalBindingWithoutTheCodeFlowRefusesCallbacks: development
// accepts CallbackBindingDeviceLocalStore on a client with no session
// store, and a callback, which needs no Session under that binding, is
// still refused rather than reaching the store the client lacks.
func TestDeviceLocalBindingWithoutTheCodeFlowRefusesCallbacks(t *testing.T) {
	cfg, deps := noCodeFlowConfig(t, false)
	cfg.Algorithms.IDToken = 0
	cfg.CallbackBinding = client.CallbackBindingDeviceLocalStore
	c, err := client.New(cfg, deps)
	if err != nil {
		t.Fatalf("New(development, device-local binding, no session store): %v", err)
	}
	checkNoCodeFlowRefusal(t, "a callback with no Session", c, client.AuthorizationCallback{
		RawQuery: url.Values{"code": {"c"}, "state": {"any-state"}, "iss": {testIssuer}}.Encode(),
	})
}

// lockedBuffer is a bytes.Buffer an http.Server's ErrorLog can write to
// from its connections' goroutines.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// issRoutingRP is a web client with one Client per issuer that routes
// each callback by the "iss" it carries, which whoever sends the
// callback chooses, rather than by a value kept with the session, as
// HandleAuthorizationResponse advises. It keeps the handle in
// client/sessioncookie's cookie.
type issRoutingRP struct {
	clients map[string]*client.Client
	cookie  *sessioncookie.Cookie
}

func (rp *issRoutingRP) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", rp.login)
	mux.HandleFunc("GET /callback", rp.callback)
	return mux
}

func (rp *issRoutingRP) login(w http.ResponseWriter, r *http.Request) {
	c, ok := rp.clients[r.URL.Query().Get("iss")]
	if !ok {
		http.Error(w, "unknown issuer", http.StatusBadRequest)
		return
	}
	session, err := c.BeginAuthorization(r.Context(), client.BeginAuthorizationRequest{Scope: []string{"openid", "accounts"}})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if err := rp.cookie.Set(w, session, "", time.Now()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (rp *issRoutingRP) callback(w http.ResponseWriter, r *http.Request) {
	handle, _, err := rp.cookie.Read(r, time.Now())
	if err != nil {
		http.Error(w, "no authorization in progress", http.StatusBadRequest)
		return
	}
	c, ok := rp.clients[r.URL.Query().Get("iss")]
	if !ok {
		http.Error(w, "unknown issuer", http.StatusBadRequest)
		return
	}
	result, err := c.CompleteAuthorization(r.Context(), client.AuthorizationCallback{RawQuery: r.URL.RawQuery, Session: handle})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if success, ok := result.(client.CompletionSuccess); ok {
		fmt.Fprintf(w, "welcome %s", success.Tokens.Subject)
		return
	}
	http.Error(w, "denied", http.StatusForbidden)
}

// getWithCookie GETs rawURL with cookie, if any, returning the response's
// status, body and cookies.
func getWithCookie(t *testing.T, rawURL string, cookie *http.Cookie) (int, string, []*http.Cookie) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cookie != nil {
		req.AddCookie(&http.Cookie{Name: cookie.Name, Value: cookie.Value})
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res.StatusCode, strings.TrimSpace(string(body)), res.Cookies()
}

// TestMisroutedCallbackToAClientWithoutTheCodeFlowOverHTTP covers an
// application serving a browser-flow issuer and a client-credentials-only
// one, routing callbacks by their "iss": a user who signs in at the
// first and sends its callback with the other's "iss" gets a 400, not a
// handler panic, and the callback still completes at the right client.
func TestMisroutedCallbackToAClientWithoutTheCodeFlowOverHTTP(t *testing.T) {
	browserFlow, as, _ := newTestClient(t, false)
	cfg, deps := noCodeFlowConfig(t, false)
	issuer, err := fapi.ParseIssuerURL(otherIssuer)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Issuer, cfg.Algorithms.IDToken = issuer, 0
	noCodeFlow, err := client.New(cfg, deps)
	if err != nil {
		t.Fatalf("New(client credentials only): %v", err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	cookie, err := sessioncookie.New([][]byte{key}, sessioncookie.Options{})
	if err != nil {
		t.Fatal(err)
	}
	rp := &issRoutingRP{clients: map[string]*client.Client{testIssuer: browserFlow, otherIssuer: noCodeFlow}, cookie: cookie}
	var serverLog lockedBuffer
	ts := httptest.NewUnstartedServer(rp.handler())
	ts.Config.ErrorLog = log.New(&serverLog, "", 0)
	ts.Start()
	t.Cleanup(ts.Close)

	status, body, cookies := getWithCookie(t, ts.URL+"/login?iss="+url.QueryEscape(testIssuer), nil)
	if status != http.StatusNoContent || len(cookies) != 1 {
		t.Fatalf("GET /login = %d %q, %d cookies; want 204 and the session cookie", status, body, len(cookies))
	}
	misrouted := url.Values{"code": {"auth-code-123"}, "state": {as.lastState}, "iss": {otherIssuer}}.Encode()
	if status, body, _ := getWithCookie(t, ts.URL+"/callback?"+misrouted, cookies[0]); status != http.StatusBadRequest || !strings.Contains(body, noCodeFlowDescription) {
		t.Fatalf("the misrouted callback = %d %q, want 400: %s", status, body, noCodeFlowDescription)
	}
	if logged := serverLog.String(); strings.Contains(logged, "http: panic serving") {
		t.Fatalf("the server recovered a handler panic:\n%s", logged)
	}
	if status, body, _ := getWithCookie(t, ts.URL+"/callback?"+as.callbackFor(t, as.lastState, "auth-code-123", ""), cookies[0]); status != http.StatusOK || body != "welcome end-user-1" {
		t.Fatalf("the callback at the right client, afterwards = %d %q, want 200: welcome end-user-1", status, body)
	}
}

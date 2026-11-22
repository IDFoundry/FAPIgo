package client_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/internal/jarm"
	"github.com/idfoundry/fapigo/keys"
)

// The descriptions a callback refused for its binding gets, before
// verification or after it alike.
const (
	notBoundDescription      = "callback is not bound to a session: pass the SessionHandle kept with this user agent as AuthorizationCallback.Session (client/sessioncookie keeps it for a browser)"
	stateMismatchDescription = "callback state does not match this user agent's session"
	missingStateDescription  = "callback is missing state"
)

// countingIssuerKeys is an IssuerKeySource counting the resolutions a
// client asks it for.
type countingIssuerKeys struct {
	keys.IssuerKeySource
	resolutions int
}

func (s *countingIssuerKeys) ResolveIssuerKeys(ctx context.Context, req keys.IssuerKeyRequest) (keys.IssuerKeySet, error) {
	s.resolutions++
	return s.IssuerKeySource.ResolveIssuerKeys(ctx, req)
}

// wrap is a newTestClientWith mutation counting the resolutions of the
// issuer keys the test client was given.
func (s *countingIssuerKeys) wrap(_ *client.Config, deps *client.Dependencies) {
	s.IssuerKeySource = deps.IssuerKeys
	deps.IssuerKeys = s
}

// pushedText is everything the most recent pushed authorization request
// sent: its form, and a request object's payload, decoded.
func (a *fakeAS) pushedText(t *testing.T) string {
	t.Helper()
	text := a.lastPARForm.Encode()
	if object := a.lastPARForm.Get("request"); object != "" {
		parts := strings.Split(object, ".")
		if len(parts) != 3 {
			t.Fatalf("request object is not a compact JWS: %q", object)
		}
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatalf("decode request object payload: %v", err)
		}
		text += string(payload)
	}
	return text
}

// stateInResponse is the state an authorization response carries, as
// anyone reading it on its way to the user agent sees it: the query
// parameter, or a JARM response's (signed, not encrypted) claim.
func stateInResponse(t *testing.T, rawQuery string) string {
	t.Helper()
	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}
	response := q.Get("response")
	if response == "" {
		return q.Get("state")
	}
	parts := strings.Split(response, ".")
	if len(parts) != 3 {
		t.Fatalf("JARM response is not a compact JWS: %q", response)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode JARM payload: %v", err)
	}
	var claims struct {
		State string `json:"state"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal JARM payload: %v", err)
	}
	return claims.State
}

// jarmResponse is the callback query of a JARM response carrying params,
// signed by signer with no kid, so every issuer key is a candidate.
func jarmResponse(t *testing.T, signer *ecdsa.PrivateKey, params map[string]string) string {
	t.Helper()
	parameters := make(map[string]json.RawMessage, len(params))
	for name, value := range params {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		parameters[name] = encoded
	}
	response, err := jarm.Create(jarm.CreateParams{
		Signer: signer, Algorithm: fapi.ES256,
		Issuer: testIssuer, Audience: testClientID,
		Now: time.Now(), Lifetime: time.Minute, Parameters: parameters,
	})
	if err != nil {
		t.Fatalf("jarm.Create: %v", err)
	}
	return url.Values{"response": {response}}.Encode()
}

// assertBindingRefusal fails t unless err is the ErrorInvalidRequest a
// callback refused for its binding gets, with description want.
func assertBindingRefusal(t *testing.T, err error, want string) {
	t.Helper()
	var cerr *client.Error
	if !errors.As(err, &cerr) || cerr.Code() != client.ErrorInvalidRequest || cerr.PublicDescription() != want {
		t.Fatalf("error = %v, want %s: %s", err, client.ErrorInvalidRequest, want)
	}
}

// TestPushedStateIsNotTheSessionHandle covers what the authorization
// server is sent, under each way a pushed request carries its
// parameters: a state that isn't the session's handle, differs per
// flow, and never the handle itself.
func TestPushedStateIsNotTheSessionHandle(t *testing.T) {
	for name, newClient := range map[string]func(*testing.T) (*client.Client, *fakeAS){
		"plain parameters": func(t *testing.T) (*client.Client, *fakeAS) {
			c, as, _ := newTestClient(t, false)
			return c, as
		},
		"request object": newTestClientWithRequestObjectEncoding,
		"message signing": func(t *testing.T) (*client.Client, *fakeAS) {
			c, as, _ := newTestClient(t, true)
			return c, as
		},
	} {
		t.Run(name, func(t *testing.T) {
			c, as := newClient(t)
			seen := map[string]bool{}
			for range 2 {
				checkPushedState(t, c, as, seen)
			}
		})
	}
}

// checkPushedState begins an authorization on c and checks the state its
// pushed request carried: as long as the session's handle, but not the
// handle, which the request doesn't carry at all, and neither a state nor
// a handle already in seen.
func checkPushedState(t *testing.T, c *client.Client, as *fakeAS, seen map[string]bool) {
	t.Helper()
	session, err := c.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{Scope: []string{"openid"}})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	handle := session.Handle().String()
	if len(as.lastState) != len(handle) || as.lastState == handle || strings.Contains(as.pushedText(t), handle) {
		t.Fatalf("pushed state %q for handle %q: want a digest of the handle, and the handle never sent", as.lastState, handle)
	}
	if seen[as.lastState] || seen[handle] {
		t.Fatalf("a state or handle repeated across flows: %q, %q", as.lastState, handle)
	}
	seen[as.lastState], seen[handle] = true, true
}

// TestCallbackStateAsTheHandleIsRefused covers whoever reads an
// authorization response before the user agent it is meant for does: its
// state, presented as the handle, is refused without consuming the
// session (under Message Signing before any issuer key is resolved), and
// the user agent that began the flow still completes it.
func TestCallbackStateAsTheHandleIsRefused(t *testing.T) {
	for name, messageSigned := range map[string]bool{"plain": false, "JARM": true} {
		t.Run(name, func(t *testing.T) { checkStateAsTheHandleRefused(t, messageSigned) })
	}
}

// checkStateAsTheHandleRefused is TestCallbackStateAsTheHandleIsRefused
// for one response mode.
func checkStateAsTheHandleRefused(t *testing.T, messageSigned bool) {
	t.Helper()
	issuerKeys := &countingIssuerKeys{}
	c, as, _ := newTestClientWith(t, messageSigned, issuerKeys.wrap)
	ctx := context.Background()
	session, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid", "accounts"}})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	response := as.callbackFor(t, as.lastState, "auth-code-123", "")
	stolen, err := client.ParseSessionHandle(stateInResponse(t, response))
	if err != nil {
		t.Fatalf("ParseSessionHandle(the response's state): %v, want it parsed: it has a handle's form", err)
	}

	_, err = c.HandleAuthorizationResponse(ctx, client.AuthorizationCallback{RawQuery: response, Session: stolen})
	assertBindingRefusal(t, err, stateMismatchDescription)
	if issuerKeys.resolutions != 0 {
		t.Fatalf("the refused callback resolved issuer keys %d times, want 0", issuerKeys.resolutions)
	}

	result, err := c.CompleteAuthorization(ctx, client.AuthorizationCallback{RawQuery: response, Session: session.Handle()})
	if err != nil {
		t.Fatalf("CompleteAuthorization with the handle, afterwards: %v", err)
	}
	if success, ok := result.(client.CompletionSuccess); !ok || success.Tokens.Subject != "end-user-1" {
		t.Fatalf("result = %#v, want the flow completed for end-user-1", result)
	}
}

// TestUnboundJARMCallbackResolvesNoIssuerKey covers the JARM responses a
// user agent's session can't accept: each is refused with the error the
// binding check gives a verified one, but before any issuer key is
// resolved or signature checked, so a forged one costs no verification,
// and none of them consumes the session.
func TestUnboundJARMCallbackResolvesNoIssuerKey(t *testing.T) {
	issuerKeys := &countingIssuerKeys{}
	c, as, _ := newTestClientWith(t, true, issuerKeys.wrap)
	ctx := context.Background()
	scope := []string{"openid", "accounts"}
	other, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: scope})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	// The fake AS issues its ID token with the most recent PAR's nonce,
	// so the flow the test completes is begun last.
	mine, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: scope})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	genuine := as.callbackFor(t, as.lastState, "auth-code-123", "")
	attackerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	forged := jarmResponse(t, attackerKey, map[string]string{"code": "attacker-code", "state": as.lastState})
	stolen, err := client.ParseSessionHandle(as.lastState)
	if err != nil {
		t.Fatal(err)
	}

	for name, tc := range map[string]struct {
		rawQuery string
		session  client.SessionHandle
		want     string
	}{
		"no Session":                       {genuine, client.SessionHandle{}, notBoundDescription},
		"another flow's Session":           {genuine, other.Handle(), stateMismatchDescription},
		"forged, no Session":               {forged, client.SessionHandle{}, notBoundDescription},
		"forged, its state as the Session": {forged, stolen, stateMismatchDescription},
		"no state":                         {jarmResponse(t, as.jarmKey, map[string]string{"code": "auth-code-123"}), mine.Handle(), missingStateDescription},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := c.HandleAuthorizationResponse(ctx, client.AuthorizationCallback{RawQuery: tc.rawQuery, Session: tc.session})
			assertBindingRefusal(t, err, tc.want)
		})
	}
	if issuerKeys.resolutions != 0 {
		t.Fatalf("refused callbacks resolved issuer keys %d times, want 0", issuerKeys.resolutions)
	}

	result, err := c.CompleteAuthorization(ctx, client.AuthorizationCallback{RawQuery: genuine, Session: mine.Handle()})
	if err != nil {
		t.Fatalf("CompleteAuthorization with the handle, afterwards: %v", err)
	}
	if _, ok := result.(client.CompletionSuccess); !ok {
		t.Fatalf("result = %T, want client.CompletionSuccess", result)
	}
	if issuerKeys.resolutions == 0 {
		t.Fatal("the genuine response resolved no issuer key: the count counts nothing")
	}
}

// plainCookieSessionName is the cookie plainCookieRP keeps the handle in.
const plainCookieSessionName = "__Host-fapi-session"

// plainCookieRP is a web client keeping each authorization's handle in a
// plain __Host- cookie, unsealed, over TLS so the cookie's Secure
// attribute holds. Nothing but the derivation of the state from the
// handle stops a party that reads the authorization response from
// presenting what it read as that cookie.
type plainCookieRP struct {
	c   *client.Client
	srv *httptest.Server
}

func newPlainCookieRP(t *testing.T, c *client.Client) *plainCookieRP {
	t.Helper()
	rp := &plainCookieRP{c: c}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", rp.login)
	mux.HandleFunc("GET /callback", rp.callback)
	rp.srv = httptest.NewTLSServer(mux)
	t.Cleanup(rp.srv.Close)
	return rp
}

// login begins an authorization and sets the cookie. The browser would
// go on to the authorization server; the test stands in for it.
func (rp *plainCookieRP) login(w http.ResponseWriter, r *http.Request) {
	session, err := rp.c.BeginAuthorization(r.Context(), client.BeginAuthorizationRequest{Scope: []string{"openid", "accounts"}})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: plainCookieSessionName, Value: session.Handle().String(),
		Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	w.WriteHeader(http.StatusNoContent)
}

// callback completes the authorization with the handle the cookie holds.
func (rp *plainCookieRP) callback(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(plainCookieSessionName)
	if err != nil {
		http.Error(w, "no authorization in progress", http.StatusBadRequest)
		return
	}
	handle, err := client.ParseSessionHandle(cookie.Value)
	if err != nil {
		http.Error(w, "malformed session", http.StatusBadRequest)
		return
	}
	result, err := rp.c.CompleteAuthorization(r.Context(), client.AuthorizationCallback{RawQuery: r.URL.RawQuery, Session: handle})
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

// browser is a user agent of its own: a cookie jar over rp's TLS
// transport.
func (rp *plainCookieRP) browser(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Transport: rp.srv.Client().Transport, Jar: jar}
}

// get has b GET path at rp, with extra as a cookie besides its jar's,
// and returns the response's status and body.
func (rp *plainCookieRP) get(t *testing.T, b *http.Client, path string, extra *http.Cookie) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, rp.srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if extra != nil {
		req.AddCookie(extra)
	}
	res, err := b.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res.StatusCode, strings.TrimSpace(string(body))
}

// begin has b sign in at rp, returning the authorization response the
// fake AS redirects b back with.
func (rp *plainCookieRP) begin(t *testing.T, as *fakeAS, b *http.Client) string {
	t.Helper()
	if status, body := rp.get(t, b, "/login", nil); status != http.StatusNoContent {
		t.Fatalf("GET /login = %d %q", status, body)
	}
	return as.callbackFor(t, as.lastState, "auth-code-123", "")
}

// TestPlainCookieRPRefusesTheResponseReader covers a web client keeping
// the handle in a plain cookie: a party that reads a victim's
// authorization response, plain or JARM, and presents the state in it
// as its own cookie is refused, and the victim's browser still signs in.
func TestPlainCookieRPRefusesTheResponseReader(t *testing.T) {
	for name, messageSigned := range map[string]bool{"plain": false, "JARM": true} {
		t.Run(name, func(t *testing.T) {
			c, as, _ := newTestClient(t, messageSigned)
			rp := newPlainCookieRP(t, c)
			victim, attacker := rp.browser(t), rp.browser(t)
			response := rp.begin(t, as, victim)

			stolen := &http.Cookie{Name: plainCookieSessionName, Value: stateInResponse(t, response)}
			if status, body := rp.get(t, attacker, "/callback?"+response, stolen); status != http.StatusBadRequest || !strings.Contains(body, stateMismatchDescription) {
				t.Fatalf("the response reader's callback = %d %q, want 400: %s", status, body, stateMismatchDescription)
			}
			if status, body := rp.get(t, victim, "/callback?"+response, nil); status != http.StatusOK || body != "welcome end-user-1" {
				t.Fatalf("the victim's callback, afterwards = %d %q, want 200: welcome end-user-1", status, body)
			}
		})
	}
}

// TestPlainCookieRPCallbackFailingBeforeConsume covers a victim's
// callback that fails before its session is consumed — it reached a
// browser without the cookie, as when an app hands it to the system
// browser — leaving the session in the store: a party that read the
// response still can't redeem it, and the victim's own browser can.
func TestPlainCookieRPCallbackFailingBeforeConsume(t *testing.T) {
	c, as, _ := newTestClient(t, false)
	rp := newPlainCookieRP(t, c)
	victim, elsewhere, attacker := rp.browser(t), rp.browser(t), rp.browser(t)
	response := rp.begin(t, as, victim)

	if status, body := rp.get(t, elsewhere, "/callback?"+response, nil); status != http.StatusBadRequest {
		t.Fatalf("the callback in a browser without the cookie = %d %q, want 400", status, body)
	}
	stolen := &http.Cookie{Name: plainCookieSessionName, Value: stateInResponse(t, response)}
	if status, body := rp.get(t, attacker, "/callback?"+response, stolen); status != http.StatusBadRequest || !strings.Contains(body, stateMismatchDescription) {
		t.Fatalf("the response reader's callback = %d %q, want 400: %s", status, body, stateMismatchDescription)
	}
	if status, body := rp.get(t, victim, "/callback?"+response, nil); status != http.StatusOK || body != "welcome end-user-1" {
		t.Fatalf("the victim's callback, afterwards = %d %q, want 200: welcome end-user-1", status, body)
	}
}

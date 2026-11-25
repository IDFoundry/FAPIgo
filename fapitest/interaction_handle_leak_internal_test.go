package fapitest

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/server/interactioncookie"
)

// These tests cover an interaction handle leaking to an attacker (a
// logged handle, say) while the user's authorization is pending at an
// embedding authorization server whose login UI signs users in from
// its own session cookie. The attacker is signed in to that server as
// themselves, and doesn't have the user's session.
//
// The handle is a bearer value: CompleteAuthorization completes it for
// whoever presents it (server.InteractionHandle's doc comment). Binding
// it to the browser that began the interaction is the embedder's job.
// An embedder that keeps the raw handle in a plain cookie binds it only
// while the handle stays secret: the attacker sets the leaked handle in
// their own browser, approves the user's interaction as themselves, and
// hands the resulting redirect to the user, whose client then signs the
// user in to the attacker's account. With server/interactioncookie the
// handle is only ever read back from a cookie the server sealed, so the
// leaked handle alone completes nothing.

const (
	leakVictimSession   = "victim-session"
	leakAttackerSession = "attacker-session"
	leakVictimSubject   = "victim-user"
	leakAttackerSubject = "attacker-user"
	leakLoginCookie     = "login"
)

// leakBridge is how an embedder carries the interaction from its
// authorization endpoint to the consent form's submission.
type leakBridge interface {
	// keep stores a in the browser's cookies on w and returns the tag
	// the consent form sends back ("" if none).
	keep(w http.ResponseWriter, a server.InteractionRequired, now time.Time) string
	// recover reads the interaction back from r and the form's tag.
	recover(r *http.Request, now time.Time, tag string) (server.InteractionHandle, server.InteractionRequest, bool)
}

// plainCookieBridge keeps the raw handle, and the encoded request, in
// plain cookies.
type plainCookieBridge struct{}

func (plainCookieBridge) keep(w http.ResponseWriter, a server.InteractionRequired, _ time.Time) string {
	in, _ := a.Interaction.MarshalText()
	http.SetCookie(w, &http.Cookie{Name: "interaction-handle", Value: a.Handle.String(), HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	http.SetCookie(w, &http.Cookie{Name: "interaction-request", Value: base64.RawURLEncoding.EncodeToString(in), HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	return ""
}

func (plainCookieBridge) recover(r *http.Request, _ time.Time, _ string) (server.InteractionHandle, server.InteractionRequest, bool) {
	hc, err1 := r.Cookie("interaction-handle")
	rc, err2 := r.Cookie("interaction-request")
	if err1 != nil || err2 != nil {
		return server.InteractionHandle{}, server.InteractionRequest{}, false
	}
	handle, err := server.ParseInteractionHandle(hc.Value)
	if err != nil {
		return server.InteractionHandle{}, server.InteractionRequest{}, false
	}
	text, err := base64.RawURLEncoding.DecodeString(rc.Value)
	if err != nil {
		return server.InteractionHandle{}, server.InteractionRequest{}, false
	}
	in, err := server.ParseInteractionRequest(string(text))
	return handle, in, err == nil
}

// sealedCookieBridge is server/interactioncookie.
type sealedCookieBridge struct{ cookie *interactioncookie.Cookie }

func (b sealedCookieBridge) keep(w http.ResponseWriter, a server.InteractionRequired, now time.Time) string {
	tag, err := b.cookie.Set(w, a, now)
	if err != nil {
		panic(err)
	}
	return tag
}

func (b sealedCookieBridge) recover(r *http.Request, now time.Time, tag string) (server.InteractionHandle, server.InteractionRequest, bool) {
	handle, in, err := b.cookie.Read(r, now, tag)
	return handle, in, err == nil
}

// leakEmbedder is the embedding authorization server's login UI.
type leakEmbedder struct {
	t      *testing.T
	h      *Harness
	bridge leakBridge
	// leaked is the handle of the last interaction begun, as a log line
	// would leak it.
	leaked string
}

// authorize is the browser reaching the authorization endpoint at
// authorizeURL: the cookies it is given and the consent form's tag.
func (e *leakEmbedder) authorize(authorizeURL url.URL) ([]*http.Cookie, string) {
	e.t.Helper()
	q := authorizeURL.Query()
	action, err := e.h.authServer.srv.BeginAuthorization(context.Background(), server.BeginAuthorizationRequest{
		RequestURI: q.Get("request_uri"), ClientID: clientIDFromQuery(q),
	})
	if err != nil {
		e.t.Fatalf("BeginAuthorization: %v", err)
	}
	a, ok := action.(server.InteractionRequired)
	if !ok {
		e.t.Fatalf("BeginAuthorization = %T, want server.InteractionRequired", action)
	}
	e.leaked = a.Handle.String()
	w := httptest.NewRecorder()
	tag := e.bridge.keep(w, a, e.h.Clock.Now())
	return w.Result().Cookies(), tag
}

// decide is a browser carrying cookies submitting the consent form
// with tag, approving as whoever its login session signs in: the
// redirect's query, or "" when the embedder refuses the submission.
func (e *leakEmbedder) decide(cookies []*http.Cookie, tag string) string {
	e.t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader(url.Values{interactioncookie.FormField: {tag}}.Encode()))
	for _, c := range cookies {
		r.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}
	login, err := r.Cookie(leakLoginCookie)
	if err != nil {
		e.t.Fatal("the browser has no login session")
	}
	subject := map[string]string{leakVictimSession: leakVictimSubject, leakAttackerSession: leakAttackerSubject}[login.Value]
	handle, in, ok := e.bridge.recover(r, e.h.Clock.Now(), tag)
	if !ok {
		return ""
	}
	result, err := e.h.authServer.srv.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
		Handle: handle, Result: server.Authorize(leakSubject(e.t, subject), leakAuthContext(e.t, e.h.Clock.Now()), server.GrantedAuthorization{Scope: in.Scope}),
	})
	if err != nil {
		e.t.Fatalf("CompleteAuthorization: %v", err)
	}
	redirect, ok := result.(server.AuthorizationRedirect)
	if !ok {
		return ""
	}
	u := redirect.Destination().URL()
	return u.RawQuery
}

func leakSubject(t *testing.T, value string) server.AuthenticatedSubject {
	t.Helper()
	id, err := server.NewSubjectID(value)
	if err != nil {
		t.Fatalf("NewSubjectID: %v", err)
	}
	subject, err := server.NewAuthenticatedSubject(id)
	if err != nil {
		t.Fatalf("NewAuthenticatedSubject: %v", err)
	}
	return subject
}

func leakAuthContext(t *testing.T, now time.Time) server.AuthenticationContext {
	t.Helper()
	authCtx, err := server.NewAuthenticationContext(now, "", nil)
	if err != nil {
		t.Fatalf("NewAuthenticationContext: %v", err)
	}
	return authCtx
}

func withLogin(session string, cookies ...*http.Cookie) []*http.Cookie {
	return append([]*http.Cookie{{Name: leakLoginCookie, Value: session}}, cookies...)
}

// beginVictim starts the victim's sign-in at h's client and has the
// victim's browser reach e's authorization endpoint: the client
// session, the victim's cookies (login session included) and form tag.
func beginVictim(t *testing.T, e *leakEmbedder) (client.AuthorizationSession, []*http.Cookie, string) {
	t.Helper()
	session, err := e.h.Client.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{Scope: []string{"openid"}})
	if err != nil {
		t.Fatalf("BeginAuthorization (client): %v", err)
	}
	cookies, tag := e.authorize(session.URL().URL())
	return session, withLogin(leakVictimSession, cookies...), tag
}

// TestLeakedHandleInPlainCookieCompletesVictimsInteraction: with the
// raw handle in a plain cookie, an attacker who learns it approves the
// victim's pending interaction as themselves, the victim's own
// submission then fails, and the redirect the attacker got, delivered
// to the victim's browser, signs the victim's client in to the
// attacker's account.
func TestLeakedHandleInPlainCookieCompletesVictimsInteraction(t *testing.T) {
	e := &leakEmbedder{t: t, h: New(t, Config{Profile: server.ProfileFAPISecurity}), bridge: plainCookieBridge{}}
	session, victimCookies, tag := beginVictim(t, e)

	var requestCookie *http.Cookie
	for _, c := range victimCookies {
		if c.Name == "interaction-request" {
			requestCookie = c
		}
	}
	attackerCookies := withLogin(leakAttackerSession,
		&http.Cookie{Name: "interaction-handle", Value: e.leaked}, requestCookie)
	callback := e.decide(attackerCookies, tag)
	if callback == "" {
		t.Fatal("the attacker's submission with the leaked handle was refused")
	}
	if victim := e.decide(victimCookies, tag); victim != "" {
		t.Errorf("the victim's own submission completed too: %s", victim)
	}

	tokens, err := e.h.RunAuthorizationCodeFlowWithCallback(context.Background(), session.Handle(), callback)
	if err != nil {
		t.Fatalf("the victim's client, given the attacker's redirect: %v", err)
	}
	if tokens.Subject != leakAttackerSubject {
		t.Errorf("the victim's client signed in as %q, want the attacker's %q", tokens.Subject, leakAttackerSubject)
	}
}

// forgedSealedCookie is the attacker's attempt at a sealed cookie
// carrying the leaked handle without the key: the format of one, under
// the key ID any sealed cookie shows, with the value unencrypted.
func forgedSealedCookie(t *testing.T, sealed *http.Cookie, handle, tag string, now time.Time) *http.Cookie {
	t.Helper()
	sealedBytes, err := base64.RawURLEncoding.DecodeString(sealed.Value)
	if err != nil || len(sealedBytes) < 5 {
		t.Fatalf("sealed cookie value %q", sealed.Value)
	}
	in, err := server.InteractionRequest{ClientID: ClientID, Scope: []string{"openid"}}.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}
	value, _ := json.Marshal(map[string]string{"tag": tag, "handle": handle, "request": string(in)})
	envelope, _ := json.Marshal(map[string]any{"exp": now.Add(time.Hour).Unix(), "v": json.RawMessage(value)})
	box := append(append([]byte{}, sealedBytes[:5]...), make([]byte, 12)...)
	return &http.Cookie{Name: sealed.Name, Value: base64.RawURLEncoding.EncodeToString(append(box, envelope...))}
}

// TestLeakedHandleIsUselessWithInteractionCookie: with
// server/interactioncookie, the leaked handle — as the cookie's value,
// or in a cookie of the sealed format the attacker made without the key
// — completes nothing, even with the victim's form tag, which isn't
// secret; the victim's own submission then completes as the victim.
func TestLeakedHandleIsUselessWithInteractionCookie(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	cookie, err := interactioncookie.New([][]byte{key}, interactioncookie.Options{})
	if err != nil {
		t.Fatalf("interactioncookie.New: %v", err)
	}
	e := &leakEmbedder{t: t, h: New(t, Config{Profile: server.ProfileFAPISecurity}), bridge: sealedCookieBridge{cookie}}
	session, victimCookies, tag := beginVictim(t, e)

	var sealed *http.Cookie
	for _, c := range victimCookies {
		if c.Name == interactioncookie.DefaultName {
			sealed = c
		}
	}
	for name, forged := range map[string]*http.Cookie{
		"raw handle":   {Name: interactioncookie.DefaultName, Value: e.leaked},
		"forged value": forgedSealedCookie(t, sealed, e.leaked, tag, e.h.Clock.Now()),
	} {
		if callback := e.decide(withLogin(leakAttackerSession, forged), tag); callback != "" {
			t.Errorf("%s: the attacker completed the victim's interaction: %s", name, callback)
		}
	}

	callback := e.decide(victimCookies, tag)
	if callback == "" {
		t.Fatal("the victim's own submission was refused")
	}
	tokens, err := e.h.RunAuthorizationCodeFlowWithCallback(context.Background(), session.Handle(), callback)
	if err != nil {
		t.Fatalf("the victim's client: %v", err)
	}
	if tokens.Subject != leakVictimSubject {
		t.Errorf("the victim's client signed in as %q, want %q", tokens.Subject, leakVictimSubject)
	}
}

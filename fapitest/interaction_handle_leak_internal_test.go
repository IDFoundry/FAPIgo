package fapitest

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
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
// leaked handle alone completes nothing. The embedder is EmbedderUI,
// with UnsafeRawHandleCookie for the plain cookie.

const (
	leakVictimSubject   = "victim-user"
	leakAttackerSubject = "attacker-user"
)

// leakEmbedder is the embedding authorization server's login UI, with
// the handle of the last interaction begun, as a log line would leak
// it.
type leakEmbedder struct {
	t      *testing.T
	h      *Harness
	ui     *EmbedderUI
	leaked string
}

// newLeakEmbedder is an EmbedderUI at a new harness's server, with the
// raw handle in a plain cookie if unsafe is set.
func newLeakEmbedder(t *testing.T, unsafe bool) *leakEmbedder {
	t.Helper()
	e := &leakEmbedder{t: t, h: New(t, Config{Profile: server.ProfileFAPISecurity})}
	e.ui = e.h.EmbedderUI(EmbedderUIOptions{
		UnsafeRawHandleCookie: unsafe,
		OnInteraction:         func(a server.InteractionRequired) { e.leaked = a.Handle.String() },
	})
	return e
}

// signIn is the session cookie e's sign-in gives subject.
func (e *leakEmbedder) signIn(subject string) *http.Cookie {
	e.t.Helper()
	return sessionCookie(e.t, e.ui, subject)
}

// authorize is the browser reaching the authorization endpoint at
// authorizeURL: the cookies it is given and the consent form's tag.
func (e *leakEmbedder) authorize(authorizeURL url.URL) ([]*http.Cookie, string) {
	e.t.Helper()
	w := serveUI(e.ui, httptest.NewRequest(http.MethodGet, EmbedderUIAuthorizePath+"?"+authorizeURL.RawQuery, nil))
	if w.Code != http.StatusOK {
		e.t.Fatalf("authorize: status %d: %s", w.Code, w.Body)
	}
	return w.Result().Cookies(), consentTag(e.t, w.Body.String())
}

// decide is a browser carrying cookies submitting the consent form
// with tag, approving as whoever its login session signs in: the
// redirect's query, or "" when the embedder refuses the submission.
func (e *leakEmbedder) decide(cookies []*http.Cookie, tag string) string {
	e.t.Helper()
	w := serveUI(e.ui, consentRequest(tag, cookies...))
	switch w.Code {
	case http.StatusSeeOther:
		u, err := url.Parse(w.Header().Get("Location"))
		if err != nil {
			e.t.Fatalf("consent redirect: %v", err)
		}
		return u.RawQuery
	case http.StatusForbidden:
		e.t.Fatal("the browser has no login session")
	case http.StatusInternalServerError:
		e.t.Fatalf("consent: %s", w.Body)
	}
	return ""
}

func withLogin(session *http.Cookie, cookies ...*http.Cookie) []*http.Cookie {
	return append([]*http.Cookie{session}, cookies...)
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
	return session, withLogin(e.signIn(leakVictimSubject), cookies...), tag
}

// TestLeakedHandleInPlainCookieCompletesVictimsInteraction: with the
// raw handle in a plain cookie, an attacker who learns it approves the
// victim's pending interaction as themselves, the victim's own
// submission then fails, and the redirect the attacker got, delivered
// to the victim's browser, signs the victim's client in to the
// attacker's account.
func TestLeakedHandleInPlainCookieCompletesVictimsInteraction(t *testing.T) {
	e := newLeakEmbedder(t, true)
	session, victimCookies, tag := beginVictim(t, e)

	var requestCookie *http.Cookie
	for _, c := range victimCookies {
		if c.Name == rawRequestCookie {
			requestCookie = c
		}
	}
	attackerCookies := withLogin(e.signIn(leakAttackerSubject),
		&http.Cookie{Name: rawHandleCookie, Value: e.leaked}, requestCookie)
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
	e := newLeakEmbedder(t, false)
	attacker := e.signIn(leakAttackerSubject)
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
		if callback := e.decide(withLogin(attacker, forged), tag); callback != "" {
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

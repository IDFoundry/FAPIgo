package fapitest

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/server/interactioncookie"
)

// consentTagField finds the consent page's tag.
var consentTagField = regexp.MustCompile(`name="` + interactioncookie.FormField + `" value="([^"]*)"`)

// consentTag is the tag the consent page body carries.
func consentTag(t *testing.T, body string) string {
	t.Helper()
	m := consentTagField.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("the consent page has no %s field: %s", interactioncookie.FormField, body)
	}
	return m[1]
}

// signInRequest is the sign-in form's submission as subject.
func signInRequest(subject string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, EmbedderUISignInPath, strings.NewReader(url.Values{EmbedderUISubjectField: {subject}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

// consentRequest is the consent form's submission with tag, from a
// browser carrying cookies.
func consentRequest(tag string, cookies ...*http.Cookie) *http.Request {
	r := httptest.NewRequest(http.MethodPost, EmbedderUIConsentPath, strings.NewReader(url.Values{interactioncookie.FormField: {tag}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		r.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}
	return r
}

// serveUI is ui's response to r.
func serveUI(ui *EmbedderUI, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	ui.ServeHTTP(w, r)
	return w
}

// beginAt starts a sign-in at h's client and has a browser reach ui's
// authorization endpoint: the client session, the cookies the browser
// is given and the consent form's tag.
func beginAt(t *testing.T, h *Harness, ui *EmbedderUI) (client.AuthorizationSession, []*http.Cookie, string) {
	t.Helper()
	session, err := h.Client.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{Scope: []string{"openid"}})
	if err != nil {
		t.Fatalf("BeginAuthorization (client): %v", err)
	}
	w := serveUI(ui, httptest.NewRequest(http.MethodGet, EmbedderUIAuthorizePath+"?"+session.URL().URL().RawQuery, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("authorize: status %d: %s", w.Code, w.Body)
	}
	return session, w.Result().Cookies(), consentTag(t, w.Body.String())
}

// sessionCookie is the session cookie ui's sign-in gives subject.
func sessionCookie(t *testing.T, ui *EmbedderUI, subject string) *http.Cookie {
	t.Helper()
	for _, c := range serveUI(ui, signInRequest(subject)).Result().Cookies() {
		if c.Name == EmbedderUISessionCookie {
			return c
		}
	}
	t.Fatal("sign-in set no session cookie")
	return nil
}

// TestEmbedderUICompletesForTheSignedInSubject drives the UI as a
// browser does, over TLS with a cookie jar: sign in, reach the
// authorization endpoint, submit the consent form; the redirect's code
// signs the client in as the signed-in subject.
func TestEmbedderUICompletesForTheSignedInSubject(t *testing.T) {
	h := New(t, Config{Profile: server.ProfileFAPISecurity})
	ts := httptest.NewTLSServer(h.EmbedderUI(EmbedderUIOptions{}))
	t.Cleanup(ts.Close)
	browser := ts.Client()
	browser.Jar, _ = cookiejar.New(nil)
	browser.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	res, err := browser.PostForm(ts.URL+EmbedderUISignInPath, url.Values{EmbedderUISubjectField: {"alice"}})
	if err != nil || res.StatusCode != http.StatusNoContent {
		t.Fatalf("sign-in: %v, %v", res, err)
	}
	_ = res.Body.Close()
	session, err := h.Client.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{Scope: []string{"openid"}})
	if err != nil {
		t.Fatalf("BeginAuthorization (client): %v", err)
	}
	tag := pageTag(t, browser, ts.URL+EmbedderUIAuthorizePath+"?"+session.URL().URL().RawQuery)
	res, err = browser.PostForm(ts.URL+EmbedderUIConsentPath, url.Values{interactioncookie.FormField: {tag}})
	if err != nil || res.StatusCode != http.StatusSeeOther {
		t.Fatalf("consent: %v, %v", res, err)
	}
	_ = res.Body.Close()
	redirect, err := url.Parse(res.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := h.RunAuthorizationCodeFlowWithCallback(context.Background(), session.Handle(), redirect.RawQuery)
	if err != nil {
		t.Fatalf("the client: %v", err)
	}
	if tokens.Subject != "alice" {
		t.Errorf("signed in as %q, want alice", tokens.Subject)
	}
}

// pageTag GETs the consent page at pageURL with browser, returning its
// tag.
func pageTag(t *testing.T, browser *http.Client, pageURL string) string {
	t.Helper()
	res, err := browser.Get(pageURL)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("authorize: status %d: %s", res.StatusCode, body)
	}
	return consentTag(t, string(body))
}

// TestEmbedderUIRefusesConsentWithoutASession: a consent submission
// carrying the interaction's cookie and tag, but no session cookie or
// one the UI never issued, completes nothing; the same browser, signed
// in, then completes the interaction.
func TestEmbedderUIRefusesConsentWithoutASession(t *testing.T) {
	h := New(t, Config{Profile: server.ProfileFAPISecurity})
	ui := h.EmbedderUI(EmbedderUIOptions{})
	_, cookies, tag := beginAt(t, h, ui)

	for name, extra := range map[string][]*http.Cookie{
		"no session":      nil,
		"unknown session": {{Name: EmbedderUISessionCookie, Value: "not-a-session"}},
	} {
		if w := serveUI(ui, consentRequest(tag, append(extra, cookies...)...)); w.Code != http.StatusForbidden {
			t.Errorf("%s: status %d, want %d", name, w.Code, http.StatusForbidden)
		}
	}
	signedIn := append([]*http.Cookie{sessionCookie(t, ui, "alice")}, cookies...)
	if w := serveUI(ui, consentRequest(tag, signedIn...)); w.Code != http.StatusSeeOther {
		t.Errorf("signed in: status %d, want %d: %s", w.Code, http.StatusSeeOther, w.Body)
	}
}

// TestEmbedderUISealsTheHandleUnlessToldNotTo: by default the
// interaction is kept only in interactioncookie's sealed cookie, and a
// submission carrying it in the raw cookies is refused;
// UnsafeRawHandleCookie alone puts the raw handle in a cookie.
func TestEmbedderUISealsTheHandleUnlessToldNotTo(t *testing.T) {
	h := New(t, Config{Profile: server.ProfileFAPISecurity})
	var handle string
	onInteraction := func(a server.InteractionRequired) { handle = a.Handle.String() }

	sealed := h.EmbedderUI(EmbedderUIOptions{OnInteraction: onInteraction})
	_, cookies, tag := beginAt(t, h, sealed)
	if len(cookies) != 1 || cookies[0].Name != interactioncookie.DefaultName || strings.Contains(cookies[0].Value, handle) {
		t.Errorf("the default UI set %v, want only the sealed %s", cookies, interactioncookie.DefaultName)
	}

	unsafe := h.EmbedderUI(EmbedderUIOptions{OnInteraction: onInteraction, UnsafeRawHandleCookie: true})
	_, raw, _ := beginAt(t, h, unsafe)
	if len(raw) != 2 || raw[0].Name != rawHandleCookie || raw[0].Value != handle || raw[1].Name != rawRequestCookie {
		t.Fatalf("UnsafeRawHandleCookie set %v, want the raw handle and request", raw)
	}
	session := sessionCookie(t, sealed, "alice")
	if w := serveUI(sealed, consentRequest(tag, append([]*http.Cookie{session}, raw...)...)); w.Code != http.StatusBadRequest {
		t.Errorf("the default UI given the raw cookies: status %d, want %d", w.Code, http.StatusBadRequest)
	}
}

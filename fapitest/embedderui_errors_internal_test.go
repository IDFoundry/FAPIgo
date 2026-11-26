package fapitest

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/idfoundry/fapigo/server"
)

// TestEmbedderUIRefusesABadSignInOrAuthorization: a sign-in naming no
// subject, and an authorization request the server can't read or
// refuses, are answered with an error, not a consent page.
func TestEmbedderUIRefusesABadSignInOrAuthorization(t *testing.T) {
	h := New(t, Config{Profile: server.ProfileFAPISecurity})
	ui := h.EmbedderUI(EmbedderUIOptions{})
	if w := serveUI(ui, signInRequest("")); w.Code != http.StatusBadRequest {
		t.Errorf("sign-in without a subject: status %d, want %d", w.Code, http.StatusBadRequest)
	}
	for name, query := range map[string]string{
		"no parameters":         "",
		"unknown request_uri":   "client_id=" + string(ClientID) + "&request_uri=urn:ietf:params:oauth:request_uri:unknown",
		"unregistered client":   "client_id=nobody&request_uri=urn:ietf:params:oauth:request_uri:unknown",
		"malformed query value": "client_id=%zz",
	} {
		w := serveUI(ui, httptest.NewRequest(http.MethodGet, EmbedderUIAuthorizePath+"?"+query, nil))
		if w.Code == http.StatusOK {
			t.Errorf("%s: status 200, want an error or a redirect to the client", name)
		}
	}
}

// TestEmbedderUIUnsafeModeRefusesUnreadableCookies: with
// UnsafeRawHandleCookie, a consent whose raw cookies are missing or
// don't parse is refused as having no sign-in in progress.
func TestEmbedderUIUnsafeModeRefusesUnreadableCookies(t *testing.T) {
	h := New(t, Config{Profile: server.ProfileFAPISecurity})
	ui := h.EmbedderUI(EmbedderUIOptions{UnsafeRawHandleCookie: true})
	_, raw, _ := beginAt(t, h, ui)
	session := sessionCookie(t, ui, "alice")
	handle, request := raw[0], raw[1]
	for name, cookies := range map[string][]*http.Cookie{
		"no raw cookies":       {session},
		"empty handle":         {session, {Name: handle.Name, Value: ""}, request},
		"request not base64":   {session, handle, {Name: request.Name, Value: "!!!"}},
		"request not readable": {session, handle, {Name: request.Name, Value: base64.RawURLEncoding.EncodeToString([]byte("{"))}},
	} {
		if w := serveUI(ui, consentRequest("", cookies...)); w.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want %d", name, w.Code, http.StatusBadRequest)
		}
	}
}

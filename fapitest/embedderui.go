package fapitest

import (
	"crypto/rand"
	"encoding/base64"
	"html/template"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/server/interactioncookie"
)

// The paths EmbedderUI serves.
const (
	// EmbedderUISignInPath signs the browser in: a POST whose form's
	// EmbedderUISubjectField names the subject, answered 204 with the
	// session cookie (EmbedderUISessionCookie) set.
	EmbedderUISignInPath = "/signin"
	// EmbedderUIAuthorizePath is the authorization endpoint: a GET with
	// the request_uri and client_id the client's authorization URL
	// carries, answered 200 with the consent page, the interaction kept
	// in the browser's cookies.
	EmbedderUIAuthorizePath = "/authorize"
	// EmbedderUIConsentPath is the consent page's form submission: a POST
	// carrying the page's interactioncookie.FormField, from a browser
	// signed in, answered 303 to the client's redirect URI.
	EmbedderUIConsentPath = "/consent"
)

const (
	// EmbedderUISubjectField is the sign-in form's field naming the
	// subject to sign in as.
	EmbedderUISubjectField = "subject"
	// EmbedderUISessionCookie is the name of the cookie EmbedderUI signs
	// a browser in with: the embedder's own session, apart from the
	// interaction's cookie.
	EmbedderUISessionCookie = "__Host-fapitest-session"
)

// The plain cookies an EmbedderUI with UnsafeRawHandleCookie keeps the
// interaction in.
const (
	rawHandleCookie  = "fapitest-interaction-handle"
	rawRequestCookie = "fapitest-interaction-request"
)

// EmbedderUIOptions configures Harness.EmbedderUI.
type EmbedderUIOptions struct {
	// OnInteraction, if set, is called with each interaction the
	// authorization endpoint begins, before the page is written: a test
	// can take the handle as a leaked log line would give it away.
	OnInteraction func(server.InteractionRequired)

	// UnsafeRawHandleCookie keeps the raw interaction handle, and the
	// encoded InteractionRequest, in plain cookies instead of sealing
	// them with server/interactioncookie. The handle is then bound to the
	// browser only while it stays secret: whoever learns it completes
	// the interaction as themselves. Set it only for a negative test of
	// that; never copy it.
	UnsafeRawHandleCookie bool
}

// EmbedderUI is a model embedding application's sign-in and consent UI
// in front of the harness's server, built from the server's and
// server/interactioncookie's public API only, so a test of an embedder
// can copy the pattern. Mount it on an httptest server (a TLS one for a
// browser-like cookie jar: its cookies are Secure) or call ServeHTTP
// directly; it serves EmbedderUISignInPath, EmbedderUIAuthorizePath and
// EmbedderUIConsentPath.
//
// It signs browsers in from its own session cookie, and keeps each
// interaction between the authorization endpoint and the consent
// submission in a cookie server/interactioncookie seals, with a key of
// its own: a consent submission completes the interaction only from
// that cookie, for the subject the browser is signed in as, granting
// what the interaction requested. Its sign-in takes the subject's name
// alone, which a real one never does, and its POSTs refuse cross-origin
// requests (net/http's CrossOriginProtection), the CSRF defence
// server.InteractionHandle's doc comment asks for.
type EmbedderUI struct {
	h       *Harness
	opts    EmbedderUIOptions
	sealed  *interactioncookie.Cookie
	handler http.Handler

	mu sync.Mutex
	// sessions maps a session cookie's value to the subject it signs
	// in.
	sessions map[string]string
}

// EmbedderUI returns a new EmbedderUI completing interactions at h's
// server.
func (h *Harness) EmbedderUI(opts EmbedderUIOptions) *EmbedderUI {
	h.t.Helper()
	key := make([]byte, 32)
	_, _ = rand.Read(key) // never fails: it crashes the program instead (Go 1.24+)
	return h.embedderUI(opts, key)
}

// embedderUI is EmbedderUI sealing its interactions with key.
func (h *Harness) embedderUI(opts EmbedderUIOptions, key []byte) *EmbedderUI {
	h.t.Helper()
	sealed, err := interactioncookie.New([][]byte{key}, interactioncookie.Options{})
	if err != nil {
		h.t.Fatalf("fapitest: interactioncookie.New: %v", err)
	}
	u := &EmbedderUI{h: h, opts: opts, sealed: sealed, sessions: map[string]string{}}
	protect := http.NewCrossOriginProtection()
	mux := http.NewServeMux()
	mux.Handle("POST "+EmbedderUISignInPath, protect.Handler(http.HandlerFunc(u.signIn)))
	mux.Handle("GET "+EmbedderUIAuthorizePath, server.AuthorizationPageHeaders(http.HandlerFunc(u.authorize)))
	mux.Handle("POST "+EmbedderUIConsentPath, server.AuthorizationPageHeaders(protect.Handler(http.HandlerFunc(u.consent))))
	u.handler = mux
	return u
}

// ServeHTTP implements http.Handler.
func (u *EmbedderUI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u.handler.ServeHTTP(w, r)
}

// signIn starts a session for the form's subject.
func (u *EmbedderUI) signIn(w http.ResponseWriter, r *http.Request) {
	subject := r.PostFormValue(EmbedderUISubjectField)
	if subject == "" {
		http.Error(w, "no subject", http.StatusBadRequest)
		return
	}
	random := make([]byte, 32)
	_, _ = rand.Read(random)
	session := base64.RawURLEncoding.EncodeToString(random)
	u.mu.Lock()
	u.sessions[session] = subject
	u.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: EmbedderUISessionCookie, Value: session, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	w.WriteHeader(http.StatusNoContent)
}

// signedIn is the subject r's session cookie signs in, if any.
func (u *EmbedderUI) signedIn(r *http.Request) (string, bool) {
	c, err := r.Cookie(EmbedderUISessionCookie)
	if err != nil {
		return "", false
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	subject, ok := u.sessions[c.Value]
	return subject, ok
}

var consentPage = template.Must(template.New("consent").Parse(`<!doctype html>
<title>Consent</title>
<p>{{.ClientID}} asks for: {{.Scope}}</p>
<form method="post" action="` + EmbedderUIConsentPath + `">
<input type="hidden" name="` + interactioncookie.FormField + `" value="{{.Tag}}">
<button>Approve</button>
</form>
`))

// authorize begins the interaction, keeps it in the browser's cookies
// and renders the consent page.
func (u *EmbedderUI) authorize(w http.ResponseWriter, r *http.Request) {
	req, err := server.BeginAuthorizationRequestFromHTTP(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	action, err := u.h.authServer.srv.BeginAuthorization(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	switch a := action.(type) {
	case server.InteractionRequired:
		if u.opts.OnInteraction != nil {
			u.opts.OnInteraction(a)
		}
		tag, err := u.keep(w, a, u.h.Clock.Now())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = consentPage.Execute(w, map[string]string{"ClientID": string(a.Interaction.ClientID), "Scope": strings.Join(a.Interaction.Scope, " "), "Tag": tag})
	case server.RedirectResponse:
		w.Header().Set("Location", a.Destination.String())
		w.WriteHeader(http.StatusFound)
	case server.LocalErrorResponse:
		http.Error(w, string(a.Error.Code())+": "+a.Error.PublicDescription(), a.Error.HTTPStatus())
	}
}

// consent completes the interaction the browser's cookies carry for the
// subject it is signed in as.
func (u *EmbedderUI) consent(w http.ResponseWriter, r *http.Request) {
	subject, ok := u.signedIn(r)
	if !ok {
		http.Error(w, "not signed in", http.StatusForbidden)
		return
	}
	now := u.h.Clock.Now()
	handle, in, ok := u.recover(r, now, r.PostFormValue(interactioncookie.FormField))
	if !ok {
		http.Error(w, "this browser has no sign-in in progress", http.StatusBadRequest)
		return
	}
	if !u.opts.UnsafeRawHandleCookie {
		u.sealed.Clear(w)
	}
	result, err := u.complete(r, handle, in, subject, now)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	switch o := result.(type) {
	case server.AuthorizationRedirect:
		// The server's redirect to the client's registered redirect URI,
		// 303 after a form POST.
		w.Header().Set("Location", o.Destination().String())
		w.WriteHeader(http.StatusSeeOther)
	case server.AuthorizationLocalError:
		http.Error(w, string(o.Error.Code())+": "+o.Error.PublicDescription(), o.Error.HTTPStatus())
	}
}

// complete approves the interaction handle names, as subject, granting
// what in requested.
func (u *EmbedderUI) complete(r *http.Request, handle server.InteractionHandle, in server.InteractionRequest, subject string, now time.Time) (server.AuthorizationResult, error) {
	id, err := server.NewSubjectID(subject)
	if err != nil {
		return nil, err
	}
	authenticated, err := server.NewAuthenticatedSubject(id)
	if err != nil {
		return nil, err
	}
	authCtx, err := server.NewAuthenticationContext(now, "", nil)
	if err != nil {
		return nil, err
	}
	return u.h.authServer.srv.CompleteAuthorization(r.Context(), server.CompleteAuthorizationRequest{
		Handle: handle,
		Result: server.Authorize(authenticated, authCtx, server.GrantedAuthorization{
			Scope: in.Scope, ApprovedIdentityClaims: in.RequestedClaims.Names(),
		}),
	})
}

// keep stores a in the browser's cookies on w, returning the tag the
// consent form sends back.
func (u *EmbedderUI) keep(w http.ResponseWriter, a server.InteractionRequired, now time.Time) (string, error) {
	if !u.opts.UnsafeRawHandleCookie {
		return u.sealed.Set(w, a, now)
	}
	encoded, err := a.Interaction.MarshalText()
	if err != nil {
		return "", err
	}
	http.SetCookie(w, &http.Cookie{Name: rawHandleCookie, Value: a.Handle.String(), Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	http.SetCookie(w, &http.Cookie{Name: rawRequestCookie, Value: base64.RawURLEncoding.EncodeToString(encoded), Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	return "", nil
}

// recover reads the interaction back from r's cookies for the form's
// tag.
func (u *EmbedderUI) recover(r *http.Request, now time.Time, tag string) (server.InteractionHandle, server.InteractionRequest, bool) {
	if !u.opts.UnsafeRawHandleCookie {
		handle, in, err := u.sealed.Read(r, now, tag)
		return handle, in, err == nil
	}
	return readRawInteraction(r)
}

// readRawInteraction reads the plain cookies UnsafeRawHandleCookie keeps
// an interaction in.
func readRawInteraction(r *http.Request) (server.InteractionHandle, server.InteractionRequest, bool) {
	hc, err1 := r.Cookie(rawHandleCookie)
	rc, err2 := r.Cookie(rawRequestCookie)
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

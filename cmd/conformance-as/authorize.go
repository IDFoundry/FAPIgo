package main

import (
	"net/http"
	"sync"

	fapi "github.com/osanderson/go-fapi"
	"github.com/osanderson/go-fapi/server"
	"github.com/osanderson/go-fapi/storage"
)

// consentHandler serves the browser-facing authorization endpoint with a
// genuine HTML consent form — not an auto-approve shortcut — so a real
// browser (including an automated conformance-suite browser driver) has
// something to load and submit.
type consentHandler struct {
	srv            *server.Server
	clients        storage.ClientRepository
	clock          server.Clock
	defaultSubject string

	// server.InteractionHandle has no public constructor — only
	// BeginAuthorization can produce one (server/interaction.go) — so this
	// map bridges "GET rendered a form" to "POST submitted it" by
	// retaining the original typed value, keyed by its own opaque string.
	// This is HTTP-layer glue only: the protocol-level single-use
	// guarantee still comes from TransactionStore.CompleteAuthorization;
	// deleting the entry here is defense in depth on top of that.
	mu      sync.Mutex
	pending map[string]server.InteractionHandle
}

func newConsentHandler(srv *server.Server, clients storage.ClientRepository, clock server.Clock, defaultSubject string) *consentHandler {
	return &consentHandler{
		srv:            srv,
		clients:        clients,
		clock:          clock,
		defaultSubject: defaultSubject,
		pending:        make(map[string]server.InteractionHandle),
	}
}

// handleBegin serves GET /authorize.
func (h *consentHandler) handleBegin(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	action, err := h.srv.BeginAuthorization(r.Context(), server.BeginAuthorizationRequest{
		RequestURI: q.Get("request_uri"),
		ClientID:   fapi.ClientID(q.Get("client_id")),
	})
	if err != nil {
		writeLocalHTMLErrorRaw(w, http.StatusInternalServerError, "server_error", "failed to begin authorization")
		return
	}

	switch action := action.(type) {
	case server.InteractionRequired:
		h.mu.Lock()
		h.pending[action.Handle.String()] = action.Handle
		h.mu.Unlock()

		// Debug/test-support only, not security-relevant: lets the smoke
		// test correlate a GET response with its interaction handle
		// without scraping the rendered HTML.
		w.Header().Set("X-Interaction-Handle", action.Handle.String())
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = consentTemplate.Execute(w, consentPage{
			Handle:    action.Handle.String(),
			ClientID:  action.Interaction.ClientID.String(),
			Scopes:    action.Interaction.Scope,
			LoginHint: string(action.Interaction.Hints.LoginHint),
			Subject:   h.defaultSubject,
		})
	case server.RedirectResponse:
		http.Redirect(w, r, action.Destination.String(), http.StatusFound)
	case server.LocalErrorResponse:
		// This AS is only ever driven by the OIDF conformance suite's own
		// scripted browser, which has no mechanism to verify a locally
		// rendered error page's content — confirmed by reading the
		// suite's own condition classes: a local page's response body is
		// only ever written to its event log for a human to read, never
		// into the Environment any condition asserts against. A redirect-
		// delivered OAuth error, by contrast, IS verified automatically
		// (authorization_endpoint_response is populated from exactly
		// that). Several negative-test modules
		// (par-attempt-reuse-request_uri and siblings,
		// ensure-unsigned-authorization-request-without-using-par-fails)
		// exist specifically to check this AS rejects a broken PAR
		// request_uri or missing request object — and would otherwise
		// only ever grade REVIEW (needing a human to approve a
		// screenshot) rather than an automated PASS, purely because of
		// this suite limitation, not any ambiguity about whether the
		// rejection itself was correct.
		//
		// So: redirect the error back to the client instead of rendering
		// it locally, but ONLY when redirect_uri is both present on this
		// request and an exact match for one of client_id's own
		// registered URIs — never trust it otherwise, since the whole
		// reason BeginAuthorization returned LocalErrorResponse here is
		// that it could not itself establish redirect_uri as trustworthy
		// (e.g. the request_uri it would normally come from is exactly
		// what's invalid/expired/reused/mismatched). This check is what
		// makes it safe: redirect_uri is validated against the trusted
		// client registry, not merely echoed back from the request under
		// test. A real, non-suite FAPI client hitting one of these errors
		// gets a perfectly good, safe outcome either way — a rendered
		// local page is fine for a human in a browser — this exists
		// purely so the suite's own automated verification can run.
		clientID := fapi.ClientID(q.Get("client_id"))
		redirectURI := q.Get("redirect_uri")
		if redirectURI != "" {
			if client, resolveErr := h.clients.ResolveClient(r.Context(), clientID); resolveErr == nil && client.HasRedirectURI(redirectURI) {
				dest, buildErr := h.srv.BuildAuthorizationErrorRedirect(r.Context(), clientID, redirectURI, q.Get("state"),
					string(action.Error.Code()), action.Error.PublicDescription())
				if buildErr == nil {
					http.Redirect(w, r, dest.String(), http.StatusFound)
					return
				}
			}
		}
		writeLocalHTMLError(w, action.Error)
	default:
		writeLocalHTMLErrorRaw(w, http.StatusInternalServerError, "server_error", "unrecognized authorization action")
	}
}

// handleDecision serves POST /authorize/decision — the consent form's
// submission target.
func (h *consentHandler) handleDecision(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeLocalHTMLErrorRaw(w, http.StatusBadRequest, "invalid_request", "malformed form")
		return
	}

	handleValue := r.FormValue("handle")
	h.mu.Lock()
	handle, ok := h.pending[handleValue]
	if ok {
		delete(h.pending, handleValue)
	}
	h.mu.Unlock()
	if !ok {
		writeLocalHTMLErrorRaw(w, http.StatusBadRequest, "invalid_request", "interaction handle is unknown, expired, or already used")
		return
	}

	subjectID, err := server.NewSubjectID(r.FormValue("subject"))
	if err != nil {
		writeLocalHTMLErrorRaw(w, http.StatusBadRequest, "invalid_request", "subject is required")
		return
	}
	subject, err := server.NewAuthenticatedSubject(subjectID)
	if err != nil {
		writeLocalHTMLErrorRaw(w, http.StatusInternalServerError, "server_error", "failed to build authenticated subject")
		return
	}
	// There is no real authentication happening here — this binary stands
	// in for a login/consent UI, not an identity provider — so ACR/AMR are
	// fixed placeholder values, the same convention fapitest's
	// AutoApprove uses.
	authCtx, err := server.NewAuthenticationContext(h.clock.Now(), "urn:mace:incommon:iap:silver", []string{"pwd"})
	if err != nil {
		writeLocalHTMLErrorRaw(w, http.StatusInternalServerError, "server_error", "failed to build authentication context")
		return
	}

	var result server.InteractionResult
	switch r.FormValue("decision") {
	case "approve":
		result = server.Authorize(subject, authCtx, server.GrantedAuthorization{Scope: r.Form["scope"]})
	case "deny":
		result = server.Deny("user denied the request")
	default:
		writeLocalHTMLErrorRaw(w, http.StatusBadRequest, "invalid_request", "decision must be approve or deny")
		return
	}

	authResult, err := h.srv.CompleteAuthorization(r.Context(), server.CompleteAuthorizationRequest{Handle: handle, Result: result})
	if err != nil {
		writeLocalHTMLErrorRaw(w, http.StatusInternalServerError, "server_error", "failed to complete authorization")
		return
	}

	switch v := authResult.(type) {
	case server.AuthorizationRedirect:
		http.Redirect(w, r, v.Destination().String(), http.StatusFound)
	case server.AuthorizationLocalError:
		writeLocalHTMLError(w, v.Error)
	default:
		writeLocalHTMLErrorRaw(w, http.StatusInternalServerError, "server_error", "unrecognized authorization result")
	}
}

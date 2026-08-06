package main

import (
	"net/http"
	"sync"

	fapi "github.com/osanderson/go-fapi"
	"github.com/osanderson/go-fapi/server"
)

// consentHandler serves the browser-facing authorization endpoint with a
// genuine HTML consent form — not an auto-approve shortcut — so a real
// browser (including an automated conformance-suite browser driver) has
// something to load and submit.
type consentHandler struct {
	srv            *server.Server
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

func newConsentHandler(srv *server.Server, clock server.Clock, defaultSubject string) *consentHandler {
	return &consentHandler{
		srv:            srv,
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

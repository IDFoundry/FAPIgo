package main

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/idfoundry/fapigo/server"
)

// pendingBackchannelAuthentication is what handleAuthenticate stashes
// per auth_req_id: the opaque handle handleApprove needs to complete
// the request, plus the scope that request asked for (needed to build
// GrantedAuthorization on approval — there is no browser-submitted
// form here to read it back from, unlike consentHandler.handleDecision),
// and any requested authorization_details, pre-approved in full — see
// approvedAuthorizationDetails' own doc comment.
type pendingBackchannelAuthentication struct {
	handle               server.BackchannelAuthenticationHandle
	scope                []string
	authorizationDetails []json.RawMessage
}

// backchannelHandler serves this binary's CIBA backchannel
// authentication endpoint, plus its own automated-approval callback —
// there is no real out-of-band device in an automated conformance run
// for a human to approve/deny on, so the OIDF suite's own
// CallAutomatedCibaApprovalEndpoint condition calls back into this
// binary instead, via a URL the suite's plan config points at
// automated_ciba_approval_url (see conformance/server/oidf-config/README.md).
// This plays the same role for CIBA that consentHandler plays for the
// browser-based flow — a stand-in for real end-user interaction, not a
// security-relevant decision-maker.
type backchannelHandler struct {
	srv            *server.Server
	clock          server.Clock
	defaultSubject string

	mu      sync.Mutex
	pending map[string]pendingBackchannelAuthentication
}

func newBackchannelHandler(srv *server.Server, clock server.Clock, defaultSubject string) *backchannelHandler {
	return &backchannelHandler{
		srv: srv, clock: clock, defaultSubject: defaultSubject,
		pending: make(map[string]pendingBackchannelAuthentication),
	}
}

// handleAuthenticate serves POST /backchannel-authenticate.
func (h *backchannelHandler) handleAuthenticate(w http.ResponseWriter, r *http.Request) {
	form, err := server.FormRequestFromHTTP(r)
	if err != nil {
		writeRawOAuthError(w, http.StatusBadRequest, server.ErrorInvalidRequest, err.Error())
		return
	}
	action, err := h.srv.BeginBackchannelAuthentication(r.Context(), server.BeginBackchannelAuthenticationRequest{
		HTTP: form, DPoPProofs: r.Header.Values("DPoP"), PeerCertificate: peerCertificate(r),
	})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	switch action := action.(type) {
	case server.BackchannelInteractionRequired:
		approved := approvedAuthorizationDetails(action.Interaction.AuthorizationDetails)
		h.mu.Lock()
		h.pending[action.AuthReqID.String()] = pendingBackchannelAuthentication{
			handle: action.Handle, scope: action.Interaction.Scope, authorizationDetails: approved,
		}
		h.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"auth_req_id": action.AuthReqID.String(),
			"expires_in":  int64(action.ExpiresIn / time.Second),
			"interval":    int64(action.Interval / time.Second),
		})
	case server.BackchannelAuthenticationLocalError:
		writeOAuthJSONError(w, action.Error)
	default:
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

// handleApprove serves POST /backchannel-approve?auth_req_id=...&action=allow|deny.
// See this type's own doc comment for why it exists; the suite's own
// CallAutomatedCibaApprovalEndpoint condition substitutes both query
// values itself from the plan config's URL template.
func (h *backchannelHandler) handleApprove(w http.ResponseWriter, r *http.Request) {
	authReqID := r.URL.Query().Get("auth_req_id")
	action := r.URL.Query().Get("action")

	h.mu.Lock()
	pending, ok := h.pending[authReqID]
	if ok {
		delete(h.pending, authReqID)
	}
	h.mu.Unlock()
	if !ok {
		http.Error(w, "unknown auth_req_id", http.StatusNotFound)
		return
	}

	var result server.InteractionResult
	switch action {
	case "allow":
		subjectID, err := server.NewSubjectID(h.defaultSubject)
		if err != nil {
			http.Error(w, "server_error", http.StatusInternalServerError)
			return
		}
		subject, err := server.NewAuthenticatedSubject(subjectID)
		if err != nil {
			http.Error(w, "server_error", http.StatusInternalServerError)
			return
		}
		// No real authentication happens here — see this binary's
		// consentHandler.handleDecision for the identical convention
		// (fixed ACR/AMR placeholder values) applied to the
		// browser-based flow.
		authCtx, err := server.NewAuthenticationContext(h.clock.Now(), "urn:mace:incommon:iap:silver", []string{"pwd"})
		if err != nil {
			http.Error(w, "server_error", http.StatusInternalServerError)
			return
		}
		result = server.Authorize(subject, authCtx, server.GrantedAuthorization{
			Scope: pending.scope, AuthorizationDetails: pending.authorizationDetails,
		})
	case "deny":
		result = server.Deny("user rejected authentication")
	default:
		http.Error(w, "action must be allow or deny", http.StatusBadRequest)
		return
	}

	if err := h.srv.CompleteBackchannelAuthentication(r.Context(), server.CompleteBackchannelAuthenticationRequest{
		Handle: pending.handle, Result: result,
	}); err != nil {
		http.Error(w, "server_error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

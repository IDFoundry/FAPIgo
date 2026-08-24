package server

import (
	"context"
	"encoding/json"
	"strings"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/par"
	"github.com/idfoundry/fapigo/storage"
)

// AuthorizationAction is a closed sum type returned by BeginAuthorization,
// so a caller can never mistake one outcome for another — in particular,
// an unvalidated redirect_uri or an unrecognized request_uri produces a
// LocalErrorResponse, never something that looks like a normal redirect.
type AuthorizationAction interface {
	authorizationAction()
}

// InteractionRequired means the embedding application must authenticate
// the resource owner (and obtain consent) before authorization can
// proceed. Handle must be passed back to CompleteAuthorization once that
// interaction concludes.
type InteractionRequired struct {
	Handle      InteractionHandle
	Interaction InteractionRequest
}

func (InteractionRequired) authorizationAction() {
	// marker method — see AuthorizationAction's own doc comment.
}

// RedirectResponse means the caller should redirect the browser to
// Destination directly, with no further interaction — e.g. a
// pre-existing session satisfies the request. No current code path
// constructs this yet; it exists now because it is part of
// BeginAuthorization's documented outcome space, and adding it later
// would be a breaking change to callers that type-switch on
// AuthorizationAction.
type RedirectResponse struct {
	Destination fapi.URL
}

func (RedirectResponse) authorizationAction() {
	// marker method — see AuthorizationAction's own doc comment.
}

// LocalErrorResponse means the caller must render a local error rather
// than redirect anywhere — the request could not be validated well
// enough to trust any redirect destination.
type LocalErrorResponse struct {
	Error *Error
}

func (LocalErrorResponse) authorizationAction() {
	// marker method — see AuthorizationAction's own doc comment.
}

// BeginAuthorizationRequest is the input to Server.BeginAuthorization —
// the request_uri and client_id query parameters presented at the
// authorization endpoint.
type BeginAuthorizationRequest struct {
	RequestURI string
	ClientID   fapi.ClientID
}

// BeginAuthorization redeems a request_uri previously obtained from
// PushAuthorizationRequest and returns what the caller should do next.
// Every outcome — including one this package cannot safely redirect
// for — is represented in the returned AuthorizationAction; the error
// return is reserved for failures outside the request itself (e.g.
// context cancellation propagating from a dependency).
func (s *Server) BeginAuthorization(ctx context.Context, req BeginAuthorizationRequest) (AuthorizationAction, error) {
	reference, ok := par.SplitRequestURI(req.RequestURI)
	if !ok {
		return s.beginFail(ctx, req.ClientID, newError(ErrorInvalidRequest, 400, "request_uri is not recognized", nil)), nil
	}
	if req.ClientID == "" {
		return s.beginFail(ctx, req.ClientID, newError(ErrorInvalidRequest, 400, "client_id is required", nil)), nil
	}

	handle, err := generateInteractionHandle(s.deps.Random)
	if err != nil {
		return s.beginFail(ctx, req.ClientID, newError(ErrorServerError, 500, "failed to generate interaction handle", err)), nil
	}

	now := s.deps.Clock.Now()
	pushed, err := s.deps.Transactions.BeginAuthorization(ctx, storage.BeginAuthorizationTransaction{
		Reference:       reference,
		Handle:          handle,
		HandleExpiresAt: now.Add(s.cfg.Limits.InteractionLifetime),
	})
	if err != nil {
		return s.beginFail(ctx, req.ClientID, newError(ErrorInvalidRequestURI, 400, "request_uri is invalid, expired, or already used", err)), nil
	}

	if pushed.ClientID != req.ClientID {
		return s.beginFail(ctx, req.ClientID, newError(ErrorInvalidRequestURI, 400, "client_id does not match the pushed authorization request", nil)), nil
	}
	if !now.Before(pushed.ExpiresAt) {
		return s.beginFail(ctx, req.ClientID, newError(ErrorInvalidRequestURI, 400, "request_uri has expired", nil)), nil
	}

	action := InteractionRequired{
		Handle:      InteractionHandle{value: handle},
		Interaction: interactionRequestFrom(req.ClientID, pushed.Parameters),
	}
	s.audit(ctx, AuditEventBeginAuthorization, req.ClientID, AuditOutcomeSuccess, "")
	return action, nil
}

func interactionRequestFrom(clientID fapi.ClientID, params map[string]json.RawMessage) InteractionRequest {
	var scopes []string
	if scope, err := jsonString(params, "scope"); err == nil && scope != "" {
		scopes = strings.Fields(scope)
	}

	var hint LoginHint
	if raw, ok := params["login_hint"]; ok {
		if v, err := jsonStringValue(raw); err == nil {
			hint = LoginHint(v)
		}
	}

	return InteractionRequest{
		ClientID: clientID,
		Scope:    scopes,
		Hints:    AuthenticationHints{LoginHint: hint},
	}
}

func (s *Server) beginFail(ctx context.Context, clientID fapi.ClientID, err *Error) AuthorizationAction {
	s.audit(ctx, AuditEventBeginAuthorization, clientID, AuditOutcomeFailure, string(err.Code()))
	return LocalErrorResponse{Error: err}
}

// BuildAuthorizationErrorRedirect builds the standard OAuth/FAPI
// authorization-error response — query parameters for plain profiles,
// a signed JARM response under ProfileFAPISecurityWithMessageSigning —
// for client at redirectURI, carrying errorCode, description and state
// (state may be empty, and is simply omitted from the response when it
// is).
//
// Unlike BeginAuthorization, which never itself returns a redirect
// destination it hasn't established as trustworthy from the request
// under validation, this method's whole purpose is to build one from a
// redirectURI the caller obtained some other way — so it checks
// redirectURI against client.HasRedirectURI itself (a client may have
// more than one registered redirect URI; any exact match is accepted)
// and returns ErrRedirectURINotRegistered rather than building a
// destination if it isn't one of client's own — returning *Error with
// ErrorInvalidRequest, the same code an OAuth redirect_uri validation
// failure earlier in the flow would carry, even though this error never
// itself reaches the client (the caller renders a local error page
// instead; see below). That check is what makes this method safe to
// call at all: without it, it would hand back a signed or
// query-parameter redirect to anywhere the caller named, reintroducing
// the open-redirect risk BeginAuthorization's LocalErrorResponse exists
// to avoid.
//
// It exists for callers — such as a conformance test harness — that
// need to present a validation failure this package can only otherwise
// express as LocalErrorResponse as a genuine redirect instead, because
// whatever is consuming the response can only verify a
// redirect-delivered error, never local page content. Ordinary FAPI
// clients have no such need — a rendered local error page is a
// perfectly good, safe outcome for a human in a browser — so
// BeginAuthorization itself is deliberately unaware this method exists.
func (s *Server) BuildAuthorizationErrorRedirect(ctx context.Context, client storage.RegisteredClient, redirectURI, state, errorCode, description string) (fapi.URL, error) {
	if !client.HasRedirectURI(redirectURI) {
		return fapi.URL{}, newError(ErrorInvalidRequest, 400, "redirect_uri is not registered for this client", nil)
	}
	dest, buildErr := s.buildAuthorizationResponse(ctx, client.ID(), redirectURI, map[string]string{
		"error": errorCode, "state": state, "error_description": description,
	})
	if buildErr != nil {
		return fapi.URL{}, buildErr
	}
	s.audit(ctx, AuditEventBeginAuthorization, client.ID(), AuditOutcomeFailure, errorCode)
	return dest, nil
}

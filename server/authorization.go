package server

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/httperror"
	"github.com/idfoundry/fapigo/internal/par"
	"github.com/idfoundry/fapigo/storage"
)

// AuthorizationAction is a closed sum type returned by BeginAuthorization,
// so a caller can never mistake one outcome for another — in particular,
// an unvalidated redirect_uri or an unrecognized request_uri produces a
// LocalErrorResponse, never something that looks like a normal redirect.
//
// Its variants are InteractionRequired, RedirectResponse and
// LocalErrorResponse; switch on the concrete type.
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

	// ExpiresAt is when Handle expires (Limits.InteractionLifetime from
	// now, by Dependencies.Clock): CompleteAuthorization refuses it after
	// that, so whatever carries the interaction until then — a cookie, a
	// session — can expire with it.
	ExpiresAt time.Time
}

// Discriminator for AuthorizationAction — deliberately empty.
func (InteractionRequired) authorizationAction() {}

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

// Discriminator for AuthorizationAction — deliberately empty.
func (RedirectResponse) authorizationAction() {}

// LocalErrorResponse means the caller must render a local error rather
// than redirect anywhere — the request could not be validated well
// enough to trust any redirect destination. Render it with
// Error.WriteText (or Code and PublicDescription in a page of your
// own); never Error.Error(), which carries internal causes.
type LocalErrorResponse struct {
	Error *Error
}

// Discriminator for AuthorizationAction — deliberately empty.
func (LocalErrorResponse) authorizationAction() {}

// BeginAuthorizationRequest is the input to Server.BeginAuthorization —
// the request_uri and client_id query parameters presented at the
// authorization endpoint.
type BeginAuthorizationRequest struct {
	RequestURI string
	ClientID   fapi.ClientID

	// Request is the request parameter (a request object, OIDC Core
	// §6.1) the authorization request carried, if any. This server takes
	// request objects only at the pushed authorization request
	// endpoint, so one sent here without a request_uri is refused with
	// ErrorRequestNotSupported; beside a request_uri it's ignored, like
	// any other parameter but client_id (RFC 9126 §4).
	// BeginAuthorizationRequestFromHTTP sets it.
	Request string
}

// BeginAuthorization redeems a request_uri previously obtained from
// PushAuthorizationRequest and returns what the caller should do next.
// Every outcome — including one this package cannot safely redirect
// for — is represented in the returned AuthorizationAction; the error
// return is reserved for failures outside the request itself (e.g.
// context cancellation propagating from a dependency).
//
// The request_uri is a bearer value in the front channel until the
// interaction completes: anyone who holds it while it's live can begin
// an interaction for the client's pushed request, and complete it as
// themselves (FAPI 2.0 Security Profile §6.4). BeginAuthorization
// accepts a request_uri more than once — a browser reloading or
// prefetching the page must not use it up (§5.3.2.2 Note 3) — but only
// one interaction for it can ever complete. Keep it out of anything a
// third party can read: serve the login page with
// "Referrer-Policy: no-referrer" and no third-party resources, and don't
// log full authorization request URLs.
func (s *Server) BeginAuthorization(ctx context.Context, req BeginAuthorizationRequest) (AuthorizationAction, error) {
	// Until it matches the client that pushed the request (below), the
	// query's client_id is only what the browser claims: those failures
	// are audited with no client (AuditEvent.ClientID), never with this
	// unverified value, which could carry anything into an audit log.
	if req.RequestURI == "" && req.Request != "" {
		// OIDC Core §6.1: an OP that doesn't support the request
		// parameter here answers request_not_supported.
		return s.beginFail(ctx, "", newError(ErrorRequestNotSupported, 400, "the request parameter is not supported at the authorization endpoint: push the request object (RFC 9126)", nil)), nil
	}
	reference, ok := par.SplitRequestURI(req.RequestURI)
	if !ok {
		return s.beginFail(ctx, "", newError(ErrorInvalidRequest, 400, "request_uri is not recognized", nil)), nil
	}
	if req.ClientID == "" {
		return s.beginFail(ctx, "", newError(ErrorInvalidRequest, 400, "client_id is required", nil)), nil
	}

	handle, err := generateInteractionHandle(s.deps.Random)
	if err != nil {
		return s.beginFail(ctx, "", newError(ErrorServerError, 500, "failed to generate interaction handle", err)), nil
	}

	now := s.deps.Clock.Now()
	handleExpiresAt := now.Add(s.cfg.Limits.InteractionLifetime)
	// Keyed by the client_id presented with it (parReferenceKey), a
	// request_uri presented with another is unknown to the store, and
	// one the store finds expired at now is refused there: neither
	// mints an interaction record.
	pushed, err := s.deps.Transactions.BeginAuthorization(ctx, storage.BeginAuthorizationTransaction{
		Reference:       parReferenceKey(req.ClientID, reference),
		Handle:          interactionHandleKey(handle),
		HandleExpiresAt: handleExpiresAt,
		Now:             now,
	})
	if err != nil {
		return s.beginFail(ctx, "", newError(ErrorInvalidRequestURI, 400, "request_uri is invalid, expired, or already used", err)), nil
	}

	// Backstops: a store keying by Reference can't return another
	// client's request, nor (keeping to its contract) an expired one.
	if pushed.ClientID != req.ClientID {
		return s.beginFail(ctx, "", newError(ErrorInvalidRequestURI, 400, "client_id does not match the pushed authorization request", nil)), nil
	}
	if !now.Before(pushed.ExpiresAt) {
		return s.beginFail(ctx, req.ClientID, newError(ErrorInvalidRequestURI, 400, "request_uri has expired", nil)), nil
	}
	// Resolved again, not carried over from the pushed request: the
	// consent screen needs its display details, and a client that has
	// since stopped resolving (e.g. a federation member whose Trust Chain
	// no longer holds) shouldn't be consented to.
	client, err := s.deps.Clients.ResolveClient(ctx, req.ClientID)
	if err != nil {
		if clientStoreUnavailable(ctx, err) {
			return s.beginFail(ctx, req.ClientID, newError(ErrorServerError, 500, "failed to look up the client", err)), nil
		}
		return s.beginFail(ctx, req.ClientID, newError(ErrorUnauthorizedClient, 400, "client is no longer registered", err)), nil
	}

	request, err := s.decodeOwnRequestRecord(pushed.Request)
	if err != nil {
		return s.beginFail(ctx, req.ClientID, recordFailure(err, newError(ErrorInvalidRequestURI, 400, "request_uri is invalid, expired, or already used", nil), "pushed authorization request")), nil
	}

	extensions, err := s.interactionExtensions(request.Parameters, coreAuthorizationParameters, request.ExtensionSource)
	if err != nil {
		return s.beginFail(ctx, req.ClientID, newError(ErrorServerError, 500, "stored extension parameters no longer validate", err)), nil
	}
	interaction := s.interactionRequestFrom(req.ClientID, request.Parameters)
	interaction.RequiredSubject = request.requiredSubjectForApplication()
	interaction.ClientDisplay = client.Display()
	interaction.Extensions = extensions
	interaction.Resources = slices.Clone(request.Resources)

	action := InteractionRequired{
		Handle:      InteractionHandle{value: handle},
		Interaction: interaction,
		ExpiresAt:   handleExpiresAt,
	}
	s.audit(ctx, AuditEventBeginAuthorization, req.ClientID, AuditOutcomeSuccess, "")
	return action, nil
}

func (s *Server) interactionRequestFrom(clientID fapi.ClientID, params map[string]json.RawMessage) InteractionRequest {
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

	// Validated at the pushed authorization request, so an error here
	// can't happen; ignoring it leaves HasMaxAge false.
	maxAge, hasMaxAge, _ := requestedMaxAge(params)
	prompt, _ := requestedPrompt(params)
	essentialACR, _ := essentialACRValues(params)
	// Validated against the client's registration at the pushed
	// authorization request; parsed here only for display.
	var redirectURI fapi.URL
	if raw, err := jsonString(params, "redirect_uri"); err == nil {
		redirectURI, _ = fapi.ParseRedirectURL(raw, fapi.AllowLoopbackHTTP(), fapi.AllowPrivateUseScheme())
	}

	return InteractionRequest{
		ClientID:             clientID,
		Scope:                scopes,
		Hints:                AuthenticationHints{LoginHint: hint},
		ACRValues:            requestedACRValues(params),
		EssentialACRValues:   essentialACR,
		MaxAge:               maxAge,
		HasMaxAge:            hasMaxAge,
		Prompt:               prompt,
		UILocales:            requestedLocales(params, "ui_locales"),
		ClaimsLocales:        requestedLocales(params, "claims_locales"),
		Display:              requestedDisplay(params),
		AuthorizationDetails: rarValuesFromStoredParameters(s.cfg.RAR, params),
		RequestedClaims:      requestedClaimsFrom(params),
		RedirectURI:          redirectURI,
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
// and, if it isn't one of client's own (or isn't an acceptable redirect
// destination for this client, as a pushed authorization request would
// have required), returns an *Error with ErrorInvalidRequest rather
// than building a destination — the same code an OAuth redirect_uri
// validation failure earlier in the flow would carry, even though this
// error never
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
//
// Under AssuranceProduction it refuses, with ErrorServerError, to build
// anything. The redirect it builds happens before any user has
// authenticated, from a request nobody pushed, which RFC 9700 §4.11.2
// forbids: the authorization server "MUST always authenticate the user
// first ... before redirecting the user", since any client — one
// registered automatically through OpenID Federation, say — can
// register its own phishing page as a redirect URI and use the server
// to bounce users there. Render a LocalErrorResponse locally instead.
func (s *Server) BuildAuthorizationErrorRedirect(ctx context.Context, client storage.RegisteredClient, redirectURI, state, errorCode, description string) (fapi.URL, error) {
	if s.cfg.Assurance == AssuranceProduction {
		return fapi.URL{}, newError(ErrorServerError, 500, "an authorization error redirect before the user has authenticated is refused under AssuranceProduction (RFC 9700 section 4.11.2)", nil)
	}
	if !client.HasRedirectURI(redirectURI) {
		return fapi.URL{}, newError(ErrorInvalidRequest, 400, "redirect_uri is not registered for this client", nil)
	}
	// What the pushed authorization request would have held it to: this
	// redirect never went through one.
	if _, err := s.parseRedirectURI(client, redirectURI); err != nil {
		return fapi.URL{}, newError(ErrorInvalidRequest, 400, "redirect_uri is not an acceptable redirect destination", err)
	}
	if !httperror.IsErrorText(errorCode) {
		return fapi.URL{}, newError(ErrorServerError, 500, "errorCode is not RFC 6749 error text", nil)
	}
	params := map[string]string{"error": errorCode, "state": state}
	// Dropped, as NewError drops one, when outside RFC 6749 §4.1.2.1's
	// error_description characters.
	if httperror.IsErrorText(description) {
		params["error_description"] = description
	}
	dest, buildErr := s.buildAuthorizationResponse(ctx, client.ID(), redirectURI, params)
	if buildErr != nil {
		return fapi.URL{}, buildErr
	}
	s.audit(ctx, AuditEventBeginAuthorization, client.ID(), AuditOutcomeFailure, errorCode)
	return dest, nil
}

// checkRedirectURIStillRegistered checks, as an interaction completes,
// that redirectURI — validated against the client's registration when
// the request was pushed — is still one of clientID's: a redirect URI
// removed since, because its host changed hands say, must not receive
// a code or an error. Either way the caller renders the failure
// locally.
func (s *Server) checkRedirectURIStillRegistered(ctx context.Context, clientID fapi.ClientID, redirectURI string) *Error {
	client, err := s.deps.Clients.ResolveClient(ctx, clientID)
	if err != nil {
		if clientStoreUnavailable(ctx, err) {
			return newError(ErrorServerError, 500, "failed to look up the client", err)
		}
		return newError(ErrorUnauthorizedClient, 400, "client is no longer registered", err)
	}
	if !client.HasRedirectURI(redirectURI) {
		return newError(ErrorInvalidRequest, 400, "redirect_uri is no longer registered for this client", nil)
	}
	return nil
}

// localDenial is DenyLocally's outcome: access_denied, rendered by the
// application, with reason as its public description when it is RFC
// 6749 error text.
func localDenial(reason string) *Error {
	if reason == "" || !httperror.IsErrorText(reason) {
		reason = "the request was declined"
	}
	return newError(ErrorAccessDenied, 403, reason, nil)
}

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/httperror"
	"github.com/idfoundry/fapigo/storage"
)

// AuthorizationResult is a closed sum type returned by
// CompleteAuthorization. Do not expose the raw authorization code or
// JARM value independently — only the complete, engine-assembled
// redirect Destination — so an embedding application cannot replace
// state, edit a JARM response, change the redirect URI, or leak a code
// into logs by handling it directly.
//
// Its variants are AuthorizationRedirect and AuthorizationLocalError;
// switch on the concrete type.
type AuthorizationResult interface {
	authorizationResult()
}

// AuthorizationRedirect means the caller should redirect the browser to
// Destination. This covers both a successful authorization (destination
// carries a code) and a denied/failed one (destination carries an OAuth
// error) — both are safe to redirect to, since the redirect_uri was
// validated when the request was pushed and is still registered for the
// client when the interaction completes.
type AuthorizationRedirect struct {
	destination fapi.URL
}

// Discriminator for AuthorizationResult — deliberately empty.
func (AuthorizationRedirect) authorizationResult() {}

// Destination returns the complete, engine-assembled redirect target.
//
// CompleteAuthorization usually runs on the submission of a login or
// consent form, a POST: redirect the browser with 303 See Other
// (http.StatusSeeOther), so it follows with a GET (FAPI 2.0 Security
// Profile §5.3.2.2). Never use 307 Temporary Redirect, which makes the
// browser re-send the form, credentials included, to the client's
// redirect URI (RFC 9700 §4.12).
func (r AuthorizationRedirect) Destination() fapi.URL { return r.destination }

// AuthorizationLocalError means the caller must render a local error
// rather than redirect anywhere — the interaction handle could not be
// validated well enough to trust the associated redirect_uri, the
// redirect_uri is no longer registered for the client, or the
// interaction ended with DenyLocally (ErrorAccessDenied). Render
// it with Error.WriteText (or Code and PublicDescription in a page of
// your own); never Error.Error(), which carries internal causes.
type AuthorizationLocalError struct {
	Error *Error
}

// Discriminator for AuthorizationResult — deliberately empty.
func (AuthorizationLocalError) authorizationResult() {}

// CompleteAuthorizationRequest is the input to Server.CompleteAuthorization.
type CompleteAuthorizationRequest struct {
	Handle InteractionHandle
	Result InteractionResult
}

// CompleteAuthorization concludes an interaction previously started by
// BeginAuthorization: it redeems Handle (single-use — a second call
// with the same handle fails), and, depending on Result, either mints an
// authorization code and returns a success redirect, or returns an
// error redirect: access_denied for Deny, login_required for
// AuthenticationFailed or for an Authorize that fails the request's
// max_age or prompt=login, and InteractionNeeded's own code. Deny and
// AuthenticationFailed redirect, so use them only once the user has
// authenticated (RFC 9700 §4.11.2); DenyLocally ends the interaction
// with an AuthorizationLocalError (access_denied) instead. A handle
// that is unknown, used or expired, a client or redirect_uri that is
// no longer registered, or a grant exceeding what was requested, is an
// AuthorizationLocalError too — never a redirect.
// Every outcome is represented in the returned AuthorizationResult; the
// error return is reserved for failures outside the request itself.
// Redirect with 303 See Other after a form POST, never 307 (see
// AuthorizationRedirect.Destination).
func (s *Server) CompleteAuthorization(ctx context.Context, req CompleteAuthorizationRequest) (AuthorizationResult, error) {
	completed, err := s.deps.Transactions.CompleteAuthorization(ctx, storage.CompleteAuthorizationTransaction{
		Handle: interactionHandleKey(req.Handle.String()),
	})
	if err != nil {
		return s.completeLocalFail(ctx, "", newError(ErrorInvalidRequest, 400, "interaction handle is invalid, expired, or already used", err)), nil
	}

	now := s.deps.Clock.Now()
	if !now.Before(completed.ExpiresAt) {
		return s.completeLocalFail(ctx, completed.ClientID, newError(ErrorInvalidRequest, 400, "interaction handle has expired", nil)), nil
	}

	request, err := s.decodeOwnRequestRecord(completed.Request)
	if err != nil {
		return s.completeLocalFail(ctx, completed.ClientID, recordFailure(err, newError(ErrorInvalidRequest, 400, "interaction handle is invalid, expired, or already used", nil), "pushed authorization request")), nil
	}

	redirectURI, err := jsonString(request.Parameters, "redirect_uri")
	if err != nil {
		return s.completeLocalFail(ctx, completed.ClientID, newError(ErrorServerError, 500, "pushed authorization request is missing redirect_uri", err)), nil
	}
	// PAR refused a state, nonce or dpop_jkt that isn't a string
	// (authorizationParameterTypes); one here would be read as absent,
	// dropping the protection the client asked for, so it fails closed.
	state, err := optionalJSONString(request.Parameters, "state")
	if err != nil {
		return s.completeLocalFail(ctx, completed.ClientID, newError(ErrorServerError, 500, "pushed authorization request has a malformed state", err)), nil
	}

	if result, ok := req.Result.(denyLocallyResult); ok {
		return s.completeLocalFail(ctx, completed.ClientID, localDenial(result.reason)), nil
	}
	if registrationErr := s.checkRedirectURIStillRegistered(ctx, completed.ClientID, redirectURI); registrationErr != nil {
		return s.completeLocalFail(ctx, completed.ClientID, registrationErr), nil
	}

	switch result := req.Result.(type) {
	case authorizeResult:
		return s.completeAuthorize(ctx, completed.ClientID, request, redirectURI, state, result)
	case denyResult:
		return s.completeErrorRedirect(ctx, completed.ClientID, redirectURI, state, "access_denied", result.reason, AuditOutcomeFailure)
	case authenticationFailedResult:
		return s.completeErrorRedirect(ctx, completed.ClientID, redirectURI, state, "login_required", result.reason, AuditOutcomeFailure)
	case interactionNeededResult:
		code := result.need.errorCode()
		if code == "" {
			return s.completeLocalFail(ctx, completed.ClientID, newError(ErrorServerError, 500, "unrecognized interaction need", nil)), nil
		}
		return s.completeErrorRedirect(ctx, completed.ClientID, redirectURI, state, code, result.reason, AuditOutcomeFailure)
	default:
		return s.completeLocalFail(ctx, completed.ClientID, newError(ErrorServerError, 500, "unrecognized interaction result", nil)), nil
	}
}

func (s *Server) completeAuthorize(ctx context.Context, clientID fapi.ClientID, request requestRecord, redirectURI, state string, result authorizeResult) (AuthorizationResult, error) {
	clientSub, sector, authorizeErr := s.checkAuthorizeResult(ctx, clientID, result)
	if authorizeErr != nil {
		return s.completeLocalFail(ctx, clientID, authorizeErr), nil
	}

	if problem := s.loginRequiredProblem(request, result.auth, clientSub); problem != "" {
		return s.completeErrorRedirect(ctx, clientID, redirectURI, state, "login_required", problem, AuditOutcomeFailure)
	}

	approved, approvedErr := s.checkApprovedGrant(request, result.grant)
	if approvedErr != nil {
		return s.completeLocalFail(ctx, clientID, approvedErr), nil
	}

	codeChallenge, err := jsonString(request.Parameters, "code_challenge")
	if err != nil {
		return s.completeLocalFail(ctx, clientID, newError(ErrorServerError, 500, "pushed authorization request is missing code_challenge", err)), nil
	}

	code, err := generateAuthorizationCode(s.deps.Random)
	if err != nil {
		return s.completeLocalFail(ctx, clientID, newError(ErrorServerError, 500, "failed to generate authorization code", err)), nil
	}
	nonce, err := optionalJSONString(request.Parameters, "nonce")
	if err != nil {
		return s.completeLocalFail(ctx, clientID, newError(ErrorServerError, 500, "pushed authorization request has a malformed nonce", err)), nil
	}
	dpopJKT, err := optionalJSONString(request.Parameters, "dpop_jkt") // optional, RFC 9449 §10
	if err != nil {
		return s.completeLocalFail(ctx, clientID, newError(ErrorServerError, 500, "pushed authorization request has a malformed dpop_jkt", err)), nil
	}

	now := s.deps.Clock.Now()
	grant, err := s.encodeGrantRecord(grantRecord{
		Kind:                    grantKindAuthorizationCode,
		IssuedAt:                &now,
		RedirectURI:             redirectURI,
		CodeChallenge:           codeChallenge,
		Nonce:                   nonce,
		DPoPJKT:                 dpopJKT,
		Subject:                 result.subject.ID().String(),
		ClientSubject:           distinctClientSubject(clientSub, result.subject.ID().String()),
		PairwiseSector:          sector,
		PairwisePrefix:          pairwisePrefixOf(s.cfg, sector),
		Scope:                   result.grant.Scope,
		AuthTime:                result.auth.authTime,
		ACR:                     result.auth.acr,
		AMR:                     result.auth.amr,
		AuthorizationDetails:    approved.authorizationDetails,
		Resources:               approved.resources,
		TokenClaims:             request.TokenClaims,
		RequestedIDTokenClaims:  approved.idTokenClaims,
		RequestedUserinfoClaims: approved.userinfoClaims,
		IDTokenClaims:           result.grant.IDTokenClaims,
		GrantID:                 result.grant.GrantID,
		ClientInstanceKey:       request.ClientInstanceKey,
		GrantType:               "authorization_code",
	})
	if err != nil {
		return s.completeLocalFail(ctx, clientID, newError(ErrorServerError, 500, "failed to encode authorization code grant", err)), nil
	}

	if err := s.deps.Grants.CreateAuthorizationCode(ctx, storage.NewAuthorizationCode{
		CodeHash:  authorizationCodeHash(code, request.ClientInstanceKey),
		ClientID:  clientID,
		Grant:     grant,
		ExpiresAt: now.Add(s.cfg.Limits.AuthorizationCodeLifetime),
	}); err != nil {
		return s.completeLocalFail(ctx, clientID, newError(ErrorServerError, 500, "failed to persist authorization code", err)), nil
	}

	destination, buildErr := s.buildAuthorizationResponse(ctx, clientID, redirectURI, map[string]string{
		"code": code, "state": state,
	})
	if buildErr != nil {
		return s.completeLocalFail(ctx, clientID, buildErr), nil
	}

	s.audit(ctx, AuditEventCompleteAuthorization, clientID, AuditOutcomeSuccess, "")
	return AuthorizationRedirect{destination: destination}, nil
}

// loginRequiredProblem describes why auth, the authentication of the
// user whose sub at the client is clientSub, doesn't meet request, so
// the client gets login_required, or returns "" when it does.
func (s *Server) loginRequiredProblem(request requestRecord, auth AuthenticationContext, clientSub string) string {
	// OIDC Core §3.1.2.1: with max_age, an authentication older than
	// max_age must be repeated, and if it isn't, the client gets an
	// error, "typically login_required" (§3.1.2.1, prompt=login).
	if maxAge, ok, _ := requestedMaxAge(request.Parameters); ok {
		oldest := s.deps.Clock.Now().Add(-maxAge - s.cfg.Limits.MaxClockSkew)
		if auth.authTime.Before(oldest) {
			return "the user's authentication is older than the requested max_age"
		}
	}

	// OIDC Core §3.1.2.1: prompt=login asks the OP to "reauthenticate the
	// End-User even if the End-User is already authenticated", and if it
	// can't, to return login_required. An authentication from before the
	// request was pushed, allowing the same clock skew as max_age, didn't
	// happen for this request. A record without PushedAt (written before
	// it existed) isn't checked.
	if prompt, _ := requestedPrompt(request.Parameters); prompt.Has(PromptLogin) && request.PushedAt != nil {
		if auth.authTime.Before(request.PushedAt.Add(-s.cfg.Limits.MaxClockSkew)) {
			return "the user didn't authenticate again for prompt=login"
		}
	}

	// OIDC Core §5.5.1.1: an essential "acr" request with values must be
	// met, or the outcome treated as a failed authentication.
	if !meetsEssentialACR(request.EssentialACRValues, auth.acr) {
		return "the user's authentication doesn't meet the requested essential acr"
	}

	// OIDC Core §5.5.1: a request naming its end user, by id_token_hint
	// or a "sub" value, must not be answered for a different one; that
	// user didn't authenticate, so it's login_required.
	if !meetsRequiredSubject(request.RequiredSubject, clientSub) {
		return "the authenticated user isn't the one the request named"
	}
	return ""
}

// approvedGrant is what an application's GrantedAuthorization approves
// of a pending authorization request, checked against it.
type approvedGrant struct {
	authorizationDetails          json.RawMessage
	resources                     []string
	idTokenClaims, userinfoClaims []string
}

// checkApprovedGrant checks grant against request, what the client
// asked for: its scope, authorization details, resources and identity
// claims may only narrow the request's, and its ID token claims and
// grant ID must be valid. Any other grant is invalid_request.
func (s *Server) checkApprovedGrant(request requestRecord, grant GrantedAuthorization) (approvedGrant, *Error) {
	requestedScope, _ := jsonString(request.Parameters, "scope")
	if err := validateGrantedScopeSubset(grant.Scope, requestedScope); err != nil {
		return approvedGrant{}, newError(ErrorInvalidRequest, 400, "granted scope is empty or exceeds requested scope", err)
	}
	details, err := s.validateGrantedAuthorizationDetails(request.Parameters[authorizationDetailsParameter], grant.AuthorizationDetails)
	if err != nil {
		return approvedGrant{}, newError(ErrorInvalidRequest, 400, "granted authorization_details exceeds what was requested", err)
	}
	resources, resourcesErr := grantedResources(request.Resources, grant.Resources)
	if resourcesErr != nil {
		return approvedGrant{}, resourcesErr
	}
	if err := validateGrantedIDTokenClaims(grant.IDTokenClaims, s.cfg.Limits.MaxIDTokenClaimsBytes); err != nil {
		return approvedGrant{}, newError(ErrorInvalidRequest, 400, "granted ID token claims are not valid", err)
	}
	if err := s.validateGrantID(grant.GrantID); err != nil {
		return approvedGrant{}, newError(ErrorInvalidRequest, 400, "the grant ID is not valid", err)
	}
	idTokenClaims, userinfoClaims, err := approvedClaimNames(request.Parameters, grant.ApprovedIdentityClaims)
	if err != nil {
		return approvedGrant{}, newError(ErrorInvalidRequest, 400, "approved identity claims exceed what was requested", err)
	}
	return approvedGrant{authorizationDetails: details, resources: resources, idTokenClaims: idTokenClaims, userinfoClaims: userinfoClaims}, nil
}

func (s *Server) completeErrorRedirect(ctx context.Context, clientID fapi.ClientID, redirectURI, state, errorCode, description string, outcome AuditOutcome) (AuthorizationResult, error) {
	params := map[string]string{"error": errorCode, "state": state}
	// description may be the application's own reason (Deny,
	// AuthenticationFailed, InteractionNeeded): one outside RFC 6749
	// §4.1.2.1's error_description characters is dropped, as NewError
	// drops one.
	if httperror.IsErrorText(description) {
		params["error_description"] = description
	}
	destination, buildErr := s.buildAuthorizationResponse(ctx, clientID, redirectURI, params)
	if buildErr != nil {
		return s.completeLocalFail(ctx, clientID, buildErr), nil
	}
	s.audit(ctx, AuditEventCompleteAuthorization, clientID, outcome, errorCode)
	return AuthorizationRedirect{destination: destination}, nil
}

// buildAuthorizationResponse assembles the final redirect target: a
// signed JARM "response" parameter under
// ProfileFAPISecurityWithMessageSigning, or plain query parameters
// otherwise. The plain path adds an "iss" parameter identifying this
// server (RFC 9207), so a client can detect a response mixed up between
// two authorization servers; a JARM response doesn't need one, since its
// own "iss" claim already serves that purpose.
func (s *Server) buildAuthorizationResponse(ctx context.Context, clientID fapi.ClientID, redirectURI string, params map[string]string) (fapi.URL, *Error) {
	base, err := url.Parse(redirectURI)
	if err != nil {
		return fapi.URL{}, newError(ErrorServerError, 500, "stored redirect_uri is malformed", err)
	}

	if s.cfg.Profile == ProfileFAPISecurityWithMessageSigning {
		responseJWT, err := s.signJARMResponse(ctx, clientID, params)
		if err != nil {
			return fapi.URL{}, newError(ErrorServerError, 500, "failed to sign authorization response", err)
		}
		q := base.Query()
		q.Set("response", responseJWT)
		base.RawQuery = q.Encode()
	} else {
		q := base.Query()
		for k, v := range params {
			if v == "" {
				continue
			}
			q.Set(k, v)
		}
		q.Set("iss", s.cfg.Issuer.String())
		base.RawQuery = q.Encode()
	}

	// The caller already held redirect_uri to the client's registered type
	// (parseRedirectURI): the pushed authorization request, or
	// BuildAuthorizationErrorRedirect. This parse only turns the value,
	// with the response parameters added, into a URL.
	destination, err := fapi.ParseRedirectURL(base.String(), fapi.AllowLoopbackHTTP(), fapi.AllowPrivateUseScheme())
	if err != nil {
		return fapi.URL{}, newError(ErrorServerError, 500, "failed to construct redirect destination", err)
	}
	return destination, nil
}

// parseRedirectURI validates raw as a redirect destination for client,
// at the pushed authorization request, so an unacceptable one is refused
// there as invalid_request rather than once the flow completes. FAPI 2.0
// §5.3.2.2 forbids http redirect URIs except a native client's loopback
// redirection (RFC 8252 §7.3):
//
//   - a native app (storage.ApplicationTypeNative) may use the
//     redirects RFC 8252 gives it — a private-use scheme, loopback http
//     or https — in production too; NewRegisteredClient checked their
//     forms;
//   - a web application may use https, and loopback http only outside
//     AssuranceProduction, the line validateAssurance draws for the
//     server's own endpoints.
func (s *Server) parseRedirectURI(client storage.RegisteredClient, raw string) (fapi.URL, error) {
	if client.ApplicationType() == storage.ApplicationTypeNative {
		return fapi.ParseRedirectURL(raw, fapi.AllowLoopbackHTTP(), fapi.AllowPrivateUseScheme())
	}
	var u fapi.URL
	var err error
	if s.cfg.Assurance == AssuranceProduction {
		u, err = fapi.ParseRedirectURL(raw)
	} else {
		u, err = fapi.ParseRedirectURL(raw, fapi.AllowLoopbackHTTP())
	}
	if err != nil {
		if _, nativeErr := fapi.ParseRedirectURL(raw, fapi.AllowLoopbackHTTP(), fapi.AllowPrivateUseScheme()); nativeErr == nil {
			// The mistake a native app's integrator makes first: say
			// which registration would admit it.
			return fapi.URL{}, fmt.Errorf("%w (a native app's redirect URI: acceptable for a client registered with ApplicationType storage.ApplicationTypeNative)", err)
		}
	}
	return u, err
}

// validateGrantedScopeSubset checks that granted, the scope a grant or a
// refreshed access token gets, holds only values of
// requestedSpaceDelimited, and at least one when that holds any: an
// empty granted scope can't be told apart from the whole request at the
// client (see GrantedAuthorization.Scope).
func validateGrantedScopeSubset(granted []string, requestedSpaceDelimited string) error {
	requested := strings.Fields(requestedSpaceDelimited)
	if len(granted) == 0 && len(requested) > 0 {
		return fmt.Errorf("no scope was granted of the requested %q; a token response without scope means the whole request was granted (RFC 6749 §5.1)", requestedSpaceDelimited)
	}
	allowed := make(map[string]struct{}, len(requested))
	for _, s := range requested {
		allowed[s] = struct{}{}
	}
	for _, g := range granted {
		if _, ok := allowed[g]; !ok {
			return fmt.Errorf("scope %q was not requested", g)
		}
	}
	return nil
}

func (s *Server) completeLocalFail(ctx context.Context, clientID fapi.ClientID, err *Error) AuthorizationResult {
	s.audit(ctx, AuditEventCompleteAuthorization, clientID, AuditOutcomeFailure, string(err.Code()))
	return AuthorizationLocalError{Error: err}
}

// checkAuthorizeResult checks what an Authorize result itself must carry
// and returns the sub the client gets for its user and the sector it was
// derived for, derived once here and kept with the grant (see
// grantRecord.ClientSubject).
func (s *Server) checkAuthorizeResult(ctx context.Context, clientID fapi.ClientID, result authorizeResult) (string, string, *Error) {
	if result.subject.id.value == "" {
		return "", "", newError(ErrorServerError, 500, "authorize result carries no authenticated subject", nil)
	}
	// The authentication time must be one that happened: a zero
	// AuthenticationContext{} would leave an ID token without the
	// auth_time max_age and prompt=login require, and a future one
	// would pass both as the most recent authentication possible.
	if problem := result.auth.authTimeProblem(s.deps.Clock.Now(), s.cfg.Limits.MaxClockSkew); problem != "" {
		return "", "", newError(ErrorServerError, 500, problem, nil)
	}
	return s.subjectAtClient(ctx, clientID, result.subject.id.value)
}

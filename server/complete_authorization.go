package server

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/url"
	"strings"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/storage"
)

// AuthorizationResult is a closed sum type returned by
// CompleteAuthorization. Do not expose the raw authorization code or
// JARM value independently — only the complete, engine-assembled
// redirect Destination — so an embedding application cannot replace
// state, edit a JARM response, change the redirect URI, or leak a code
// into logs by handling it directly.
type AuthorizationResult interface {
	authorizationResult()
}

// AuthorizationRedirect means the caller should redirect the browser to
// Destination. This covers both a successful authorization (destination
// carries a code) and a denied/failed one (destination carries an OAuth
// error) — both are safe to redirect to, since the redirect_uri was
// already validated when the request was pushed.
type AuthorizationRedirect struct {
	destination fapi.URL
}

// Discriminator for AuthorizationResult — deliberately empty.
func (AuthorizationRedirect) authorizationResult() {}

// Destination returns the complete, engine-assembled redirect target.
func (r AuthorizationRedirect) Destination() fapi.URL { return r.destination }

// AuthorizationLocalError means the caller must render a local error
// rather than redirect anywhere — the interaction handle could not be
// validated well enough to trust the associated redirect_uri.
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
// max_age or prompt=login, and InteractionNeeded's own code. A handle
// that is unknown, used or expired, or a grant exceeding what was
// requested, is an AuthorizationLocalError instead — never a redirect.
// Every outcome is represented in the returned AuthorizationResult; the
// error return is reserved for failures outside the request itself.
func (s *Server) CompleteAuthorization(ctx context.Context, req CompleteAuthorizationRequest) (AuthorizationResult, error) {
	completed, err := s.deps.Transactions.CompleteAuthorization(ctx, storage.CompleteAuthorizationTransaction{
		Handle: req.Handle.String(),
	})
	if err != nil {
		return s.completeLocalFail(ctx, "", newError(ErrorInvalidRequest, 400, "interaction handle is invalid, expired, or already used", err)), nil
	}

	now := s.deps.Clock.Now()
	if !now.Before(completed.ExpiresAt) {
		return s.completeLocalFail(ctx, completed.ClientID, newError(ErrorInvalidRequest, 400, "interaction handle has expired", nil)), nil
	}

	request, err := decodeRequestRecord(completed.Request)
	if err != nil {
		return s.completeLocalFail(ctx, completed.ClientID, newError(ErrorServerError, 500, "failed to decode pushed authorization request", err)), nil
	}

	redirectURI, err := jsonString(request.Parameters, "redirect_uri")
	if err != nil {
		return s.completeLocalFail(ctx, completed.ClientID, newError(ErrorServerError, 500, "pushed authorization request is missing redirect_uri", err)), nil
	}
	state, _ := jsonString(request.Parameters, "state")

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
	if result.subject.id.value == "" {
		return s.completeLocalFail(ctx, clientID, newError(ErrorServerError, 500, "authorize result carries no authenticated subject", nil)), nil
	}

	// OIDC Core §3.1.2.1: with max_age, an authentication older than
	// max_age must be repeated, and if it isn't, the client gets an
	// error, "typically login_required" (§3.1.2.1, prompt=login).
	if maxAge, ok, _ := requestedMaxAge(request.Parameters); ok {
		oldest := s.deps.Clock.Now().Add(-maxAge - s.cfg.Limits.MaxClockSkew)
		if result.auth.authTime.Before(oldest) {
			return s.completeErrorRedirect(ctx, clientID, redirectURI, state, "login_required", "the user's authentication is older than the requested max_age", AuditOutcomeFailure)
		}
	}

	// OIDC Core §3.1.2.1: prompt=login asks the OP to "reauthenticate the
	// End-User even if the End-User is already authenticated", and if it
	// can't, to return login_required. An authentication from before the
	// request was pushed, allowing the same clock skew as max_age, didn't
	// happen for this request. A record without PushedAt (written before
	// it existed) isn't checked.
	if prompt, _ := requestedPrompt(request.Parameters); prompt.Has(PromptLogin) && request.PushedAt != nil {
		if result.auth.authTime.Before(request.PushedAt.Add(-s.cfg.Limits.MaxClockSkew)) {
			return s.completeErrorRedirect(ctx, clientID, redirectURI, state, "login_required", "the user didn't authenticate again for prompt=login", AuditOutcomeFailure)
		}
	}

	requestedScope, _ := jsonString(request.Parameters, "scope")
	if err := validateGrantedScopeSubset(result.grant.Scope, requestedScope); err != nil {
		return s.completeLocalFail(ctx, clientID, newError(ErrorInvalidRequest, 400, "granted scope exceeds requested scope", err)), nil
	}

	grantedAuthorizationDetails, err := s.validateGrantedAuthorizationDetails(request.Parameters[authorizationDetailsParameter], result.grant.AuthorizationDetails)
	if err != nil {
		return s.completeLocalFail(ctx, clientID, newError(ErrorInvalidRequest, 400, "granted authorization_details exceeds what was requested", err)), nil
	}

	if err := validateGrantedIDTokenClaims(result.grant.IDTokenClaims, s.cfg.Limits.MaxIDTokenClaimsBytes); err != nil {
		return s.completeLocalFail(ctx, clientID, newError(ErrorInvalidRequest, 400, "granted ID token claims are not valid", err)), nil
	}
	if err := s.validateGrantID(result.grant.GrantID); err != nil {
		return s.completeLocalFail(ctx, clientID, newError(ErrorInvalidRequest, 400, "the grant ID is not valid", err)), nil
	}

	idTokenClaims, userinfoClaims, err := approvedClaimNames(request.Parameters, result.grant.ApprovedIdentityClaims)
	if err != nil {
		return s.completeLocalFail(ctx, clientID, newError(ErrorInvalidRequest, 400, "approved identity claims exceed what was requested", err)), nil
	}

	codeChallenge, err := jsonString(request.Parameters, "code_challenge")
	if err != nil {
		return s.completeLocalFail(ctx, clientID, newError(ErrorServerError, 500, "pushed authorization request is missing code_challenge", err)), nil
	}

	code, err := generateAuthorizationCode(s.deps.Random)
	if err != nil {
		return s.completeLocalFail(ctx, clientID, newError(ErrorServerError, 500, "failed to generate authorization code", err)), nil
	}
	nonce, _ := jsonString(request.Parameters, "nonce")
	dpopJKT, _ := jsonString(request.Parameters, "dpop_jkt") // optional, RFC 9449 §10

	now := s.deps.Clock.Now()
	grant, err := encodeGrantRecord(grantRecord{
		IssuedAt:                &now,
		RedirectURI:             redirectURI,
		CodeChallenge:           codeChallenge,
		Nonce:                   nonce,
		DPoPJKT:                 dpopJKT,
		Subject:                 result.subject.ID().String(),
		Scope:                   result.grant.Scope,
		AuthTime:                result.auth.authTime,
		ACR:                     result.auth.acr,
		AMR:                     result.auth.amr,
		AuthorizationDetails:    grantedAuthorizationDetails,
		TokenClaims:             request.TokenClaims,
		RequestedIDTokenClaims:  idTokenClaims,
		RequestedUserinfoClaims: userinfoClaims,
		IDTokenClaims:           result.grant.IDTokenClaims,
		GrantID:                 result.grant.GrantID,
	})
	if err != nil {
		return s.completeLocalFail(ctx, clientID, newError(ErrorServerError, 500, "failed to encode authorization code grant", err)), nil
	}

	if err := s.deps.Grants.CreateAuthorizationCode(ctx, storage.NewAuthorizationCode{
		CodeHash:  sha256.Sum256([]byte(code)),
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

func (s *Server) completeErrorRedirect(ctx context.Context, clientID fapi.ClientID, redirectURI, state, errorCode, description string, outcome AuditOutcome) (AuthorizationResult, error) {
	params := map[string]string{"error": errorCode, "state": state}
	if description != "" {
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

func validateGrantedScopeSubset(granted []string, requestedSpaceDelimited string) error {
	allowed := make(map[string]struct{}, len(granted))
	for _, s := range strings.Fields(requestedSpaceDelimited) {
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

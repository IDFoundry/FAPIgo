package server

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/url"
	"strings"

	fapi "github.com/osanderson/go-fapi"
	"github.com/osanderson/go-fapi/storage"
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

func (AuthorizationRedirect) authorizationResult() {}

// Destination returns the complete, engine-assembled redirect target.
func (r AuthorizationRedirect) Destination() fapi.URL { return r.destination }

// AuthorizationLocalError means the caller must render a local error
// rather than redirect anywhere — the interaction handle could not be
// validated well enough to trust the associated redirect_uri.
type AuthorizationLocalError struct {
	Error *Error
}

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
// error redirect. Every outcome is represented in the returned
// AuthorizationResult; the error return is reserved for failures
// outside the request itself.
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

	redirectURI, err := jsonString(completed.Parameters, "redirect_uri")
	if err != nil {
		return s.completeLocalFail(ctx, completed.ClientID, newError(ErrorServerError, 500, "pushed authorization request is missing redirect_uri", err)), nil
	}
	state, _ := jsonString(completed.Parameters, "state")

	switch result := req.Result.(type) {
	case authorizeResult:
		return s.completeAuthorize(ctx, completed, redirectURI, state, result)
	case denyResult:
		return s.completeErrorRedirect(ctx, completed.ClientID, redirectURI, state, "access_denied", result.reason, AuditOutcomeFailure)
	case authenticationFailedResult:
		return s.completeErrorRedirect(ctx, completed.ClientID, redirectURI, state, "login_required", result.reason, AuditOutcomeFailure)
	default:
		return s.completeLocalFail(ctx, completed.ClientID, newError(ErrorServerError, 500, "unrecognized interaction result", nil)), nil
	}
}

func (s *Server) completeAuthorize(ctx context.Context, completed storage.CompletedInteraction, redirectURI, state string, result authorizeResult) (AuthorizationResult, error) {
	if result.subject.id.value == "" {
		return s.completeLocalFail(ctx, completed.ClientID, newError(ErrorServerError, 500, "authorize result carries no authenticated subject", nil)), nil
	}

	requestedScope, _ := jsonString(completed.Parameters, "scope")
	if err := validateGrantedScopeSubset(result.grant.Scope, requestedScope); err != nil {
		return s.completeLocalFail(ctx, completed.ClientID, newError(ErrorInvalidRequest, 400, "granted scope exceeds requested scope", err)), nil
	}

	codeChallenge, err := jsonString(completed.Parameters, "code_challenge")
	if err != nil {
		return s.completeLocalFail(ctx, completed.ClientID, newError(ErrorServerError, 500, "pushed authorization request is missing code_challenge", err)), nil
	}

	code, err := generateAuthorizationCode(s.deps.Random)
	if err != nil {
		return s.completeLocalFail(ctx, completed.ClientID, newError(ErrorServerError, 500, "failed to generate authorization code", err)), nil
	}
	nonce, _ := jsonString(completed.Parameters, "nonce")

	now := s.deps.Clock.Now()
	if err := s.deps.Grants.CreateAuthorizationCode(ctx, storage.NewAuthorizationCode{
		CodeHash:            sha256.Sum256([]byte(code)),
		ClientID:            completed.ClientID,
		RedirectURI:         redirectURI,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: "S256",
		Subject:             result.subject.ID().String(),
		Scope:               result.grant.Scope,
		Nonce:               nonce,
		AuthTime:            result.auth.authTime,
		ACR:                 result.auth.acr,
		AMR:                 result.auth.amr,
		ExpiresAt:           now.Add(s.cfg.Limits.AuthorizationCodeLifetime),
	}); err != nil {
		return s.completeLocalFail(ctx, completed.ClientID, newError(ErrorServerError, 500, "failed to persist authorization code", err)), nil
	}

	destination, buildErr := s.buildAuthorizationResponse(ctx, completed.ClientID, redirectURI, map[string]string{
		"code": code, "state": state,
	})
	if buildErr != nil {
		return s.completeLocalFail(ctx, completed.ClientID, buildErr), nil
	}

	s.audit(ctx, AuditEventCompleteAuthorization, completed.ClientID, AuditOutcomeSuccess, "")
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

	destination, err := fapi.ParseEndpointURL(base.String())
	if err != nil {
		return fapi.URL{}, newError(ErrorServerError, 500, "failed to construct redirect destination", err)
	}
	return destination, nil
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

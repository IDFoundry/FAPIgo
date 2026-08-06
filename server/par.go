package server

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	fapi "github.com/osanderson/go-fapi"
	"github.com/osanderson/go-fapi/extension"
	"github.com/osanderson/go-fapi/internal/clientassertion"
	"github.com/osanderson/go-fapi/internal/par"
	"github.com/osanderson/go-fapi/internal/pkce"
	"github.com/osanderson/go-fapi/internal/requestobject"
	"github.com/osanderson/go-fapi/keys"
	"github.com/osanderson/go-fapi/storage"
)

// coreAuthorizationParameters are the standard OAuth/OIDC/PKCE
// authorization request parameters this package understands natively —
// excluded from Config.Extensions' unregistered-parameter check, since
// they are not custom parameters.
var coreAuthorizationParameters = map[string]struct{}{
	"response_type": {}, "client_id": {}, "redirect_uri": {}, "scope": {},
	"state": {}, "nonce": {}, "code_challenge": {}, "code_challenge_method": {},
	"login_hint": {},
}

// FormParameter is one name/value pair from a form-encoded request body,
// in the order it appeared on the wire.
type FormParameter struct {
	Name  string
	Value string
}

// FormRequest is the raw, lossless representation of an inbound
// application/x-www-form-urlencoded request this package's endpoints
// accept. It is lossless specifically so this package — not an HTTP
// adapter — detects duplicate or malformed parameters, rather than
// trusting a pre-parsed url.Values that may already have collapsed
// them.
type FormRequest struct {
	Parameters []FormParameter
}

// PushAuthorizationRequest is the input to Server.PushAuthorizationRequest.
type PushAuthorizationRequest struct {
	HTTP FormRequest
}

// PushAuthorizationResult is returned by a successful
// PushAuthorizationRequest.
type PushAuthorizationResult struct {
	RequestURI RequestURI
	ExpiresIn  time.Duration
}

// PushAuthorizationRequest authenticates the client, verifies either its
// signed request object or its plain authorization parameters (per
// Config.Profile), validates them against the client's registration, and
// stores them for later retrieval at the authorization endpoint.
func (s *Server) PushAuthorizationRequest(ctx context.Context, req PushAuthorizationRequest) (PushAuthorizationResult, error) {
	params, err := formParametersToMap(req.HTTP.Parameters)
	if err != nil {
		return s.parFail(ctx, "", newError(ErrorInvalidRequest, 400, "the request contains a duplicated parameter", err))
	}

	client, _, authErr := s.authenticateClient(ctx, params)
	if authErr != nil {
		var clientID fapi.ClientID
		return s.parFail(ctx, clientID, authErr)
	}

	authParams, tokenClaims, resolveErr := s.resolveAuthorizationParameters(ctx, params, client)
	if resolveErr != nil {
		return s.parFail(ctx, client.ID(), resolveErr)
	}

	validated, validateErr := s.validateAuthorizationParameters(authParams, client)
	if validateErr != nil {
		return s.parFail(ctx, client.ID(), validateErr)
	}

	requestURI, err := par.GenerateRequestURI(s.deps.Random)
	if err != nil {
		return s.parFail(ctx, client.ID(), newError(ErrorServerError, 500, "failed to generate request_uri", err))
	}
	reference, _ := par.SplitRequestURI(requestURI)

	now := s.deps.Clock.Now()
	expiresAt := now.Add(s.cfg.Limits.PushedRequestLifetime)

	if err := s.deps.Transactions.CreatePAR(ctx, storage.NewPARRecord{
		Reference:   reference,
		ClientID:    client.ID(),
		Parameters:  validated,
		TokenClaims: tokenClaims,
		ExpiresAt:   expiresAt,
	}); err != nil {
		return s.parFail(ctx, client.ID(), newError(ErrorServerError, 500, "failed to persist pushed authorization request", err))
	}

	s.audit(ctx, AuditEventPushAuthorizationRequest, client.ID(), AuditOutcomeSuccess, "")
	return PushAuthorizationResult{
		RequestURI: RequestURI{value: requestURI},
		ExpiresIn:  s.cfg.Limits.PushedRequestLifetime,
	}, nil
}

// authenticateClient verifies the request's client_assertion and
// resolves the registered client it identifies.
func (s *Server) authenticateClient(ctx context.Context, params map[string]string) (storage.RegisteredClient, clientassertion.VerifiedAssertion, *Error) {
	assertionRaw, ok := params["client_assertion"]
	if !ok || assertionRaw == "" {
		return storage.RegisteredClient{}, clientassertion.VerifiedAssertion{},
			newError(ErrorInvalidClient, 401, "client authentication is required", nil)
	}
	if params["client_assertion_type"] != clientassertion.AssertionType {
		return storage.RegisteredClient{}, clientassertion.VerifiedAssertion{},
			newError(ErrorInvalidClient, 401, "unsupported client_assertion_type", nil)
	}

	assertion, err := clientassertion.Parse(assertionRaw)
	if err != nil {
		return storage.RegisteredClient{}, clientassertion.VerifiedAssertion{},
			newError(ErrorInvalidClient, 401, "malformed client assertion", err)
	}

	client, err := s.deps.Clients.ResolveClient(ctx, fapi.ClientID(assertion.ClaimedSubject()))
	if err != nil {
		return storage.RegisteredClient{}, clientassertion.VerifiedAssertion{},
			newError(ErrorInvalidClient, 401, "unknown client", err)
	}

	if !s.cfg.Algorithms.ClientAssertion.Contains(client.ClientAssertionAlgorithm()) {
		return storage.RegisteredClient{}, clientassertion.VerifiedAssertion{},
			newError(ErrorInvalidClient, 401, "client assertion algorithm is not permitted", nil)
	}

	pub, err := s.resolveClientKey(ctx, client.ID(), keys.ClientAssertionVerification, client.ClientAssertionAlgorithm(), assertion.KeyID())
	if err != nil {
		return storage.RegisteredClient{}, clientassertion.VerifiedAssertion{},
			newError(ErrorInvalidClient, 401, "no matching client key", err)
	}

	verified, err := assertion.Verify(ctx, pub, clientassertion.VerifyPolicy{
		ExpectedClientID: client.ID().String(),
		ExpectedAudience: s.cfg.Issuer.String(),
		Algorithm:        client.ClientAssertionAlgorithm(),
		Now:              s.deps.Clock.Now(),
		MaxLifetime:      s.cfg.Limits.MaxClientAssertionLifetime,
		MaxClockSkew:     s.cfg.Limits.MaxClockSkew,
		Replay:           s.clientAssertionReplayChecker(),
	})
	if err != nil {
		return storage.RegisteredClient{}, clientassertion.VerifiedAssertion{},
			newError(ErrorInvalidClient, 401, "client assertion verification failed", err)
	}

	return client, verified, nil
}

// resolveAuthorizationParameters returns the pushed authorization
// request's parameters, either by verifying a signed request object (the
// "request" parameter) or, when Config.Profile permits it, by taking
// them directly from the plain form parameters — plus the subset of
// those parameters (extension.Definition.ReturnInTokenClaims) that
// should be copied into any token this authorization eventually issues.
func (s *Server) resolveAuthorizationParameters(ctx context.Context, params map[string]string, client storage.RegisteredClient) (map[string]json.RawMessage, map[string]json.RawMessage, *Error) {
	requestParam, hasRequestParam := params["request"]

	if !hasRequestParam {
		if s.cfg.Profile == ProfileFAPISecurityWithMessageSigning {
			return nil, nil, newError(ErrorInvalidRequest, 400, "a signed request object is required", nil)
		}
		plain := plainParamsToJSON(params)
		tokenClaims, err := s.checkExtensions(plain, extension.SourcePlainParameter)
		if err != nil {
			return nil, nil, err
		}
		return plain, tokenClaims, nil
	}

	alg, permitted := client.RequestObjectAlgorithm()
	if !permitted {
		return nil, nil, newError(ErrorInvalidRequestObject, 400, "client is not permitted to submit request objects", nil)
	}
	if !s.cfg.Algorithms.RequestObject.Contains(alg) {
		return nil, nil, newError(ErrorInvalidRequestObject, 400, "request object algorithm is not permitted", nil)
	}

	obj, err := requestobject.Parse(requestParam)
	if err != nil {
		return nil, nil, newError(ErrorInvalidRequestObject, 400, "malformed request object", err)
	}

	pub, err := s.resolveClientKey(ctx, client.ID(), keys.RequestObjectVerification, alg, obj.KeyID())
	if err != nil {
		return nil, nil, newError(ErrorInvalidRequestObject, 400, "no matching client key", err)
	}

	verified, err := obj.Verify(ctx, pub, requestobject.VerifyPolicy{
		ExpectedClientID: client.ID().String(),
		ExpectedAudience: s.cfg.Issuer.String(),
		Algorithm:        alg,
		Now:              s.deps.Clock.Now(),
		MaxLifetime:      s.cfg.Limits.MaxRequestObjectLifetime,
		MaxClockSkew:     s.cfg.Limits.MaxClockSkew,
		Replay:           s.requestObjectReplayChecker(),
	})
	if err != nil {
		return nil, nil, newError(ErrorInvalidRequestObject, 400, "request object verification failed", err)
	}
	tokenClaims, checkErr := s.checkExtensions(verified.Parameters, extension.SourceRequestObject)
	if checkErr != nil {
		return nil, nil, checkErr
	}
	return verified.Parameters, tokenClaims, nil
}

// checkExtensions validates every non-core parameter in params against
// Config.Extensions, rejecting any name without a registered Definition
// (Config.Extensions is never nil once New has run — see server.New),
// and returns the claims-eligible subset (ReturnInTokenClaims) ready to
// copy into a future access/ID token.
func (s *Server) checkExtensions(params map[string]json.RawMessage, source extension.Source) (map[string]json.RawMessage, *Error) {
	values, err := s.cfg.Extensions.Parse(params, coreAuthorizationParameters, source)
	if err != nil {
		return nil, newError(ErrorInvalidRequest, 400, "request contains an unregistered or invalid parameter", err)
	}
	return extension.AsParameters(values, s.cfg.Extensions.Definitions()...), nil
}

// resolveClientKey picks the verification key matching kid/alg from
// whatever ClientKeys returns for the client.
func (s *Server) resolveClientKey(ctx context.Context, id fapi.ClientID, purpose keys.VerificationPurpose, alg fapi.SignatureAlgorithm, kid string) (crypto.PublicKey, error) {
	set, err := s.deps.ClientKeys.ResolveVerificationKeys(ctx, keys.ClientKeyRequest{
		ClientID: id, Purpose: purpose, Algorithm: alg, KeyID: kid,
	})
	if err != nil {
		return nil, err
	}
	for _, k := range set.Keys {
		if kid != "" && k.KeyID != kid {
			continue
		}
		if k.Algorithm != alg {
			continue
		}
		return k.PublicKey, nil
	}
	return nil, fmt.Errorf("no verification key found for kid=%q algorithm=%v", kid, alg)
}

// validateAuthorizationParameters checks the FAPI-mandated authorization
// parameters (response_type, redirect_uri, PKCE, and scope if present)
// against client. It returns params unmodified on success; every other
// parameter is stored as-is for the authorization endpoint to interpret.
func (s *Server) validateAuthorizationParameters(params map[string]json.RawMessage, client storage.RegisteredClient) (map[string]json.RawMessage, *Error) {
	responseType, err := jsonString(params, "response_type")
	if err != nil || responseType != "code" {
		return nil, newError(ErrorInvalidRequest, 400, `response_type must be "code"`, err)
	}

	redirectURI, err := jsonString(params, "redirect_uri")
	if err != nil {
		return nil, newError(ErrorInvalidRequest, 400, "redirect_uri is required", err)
	}
	if !client.HasRedirectURI(redirectURI) {
		return nil, newError(ErrorInvalidRequest, 400, "redirect_uri is not registered for this client", nil)
	}

	codeChallenge, err := jsonString(params, "code_challenge")
	if err != nil {
		return nil, newError(ErrorInvalidRequest, 400, "code_challenge is required", err)
	}
	if codeChallenge == "" {
		return nil, newError(ErrorInvalidRequest, 400, "code_challenge must not be empty", nil)
	}
	codeChallengeMethod, err := jsonString(params, "code_challenge_method")
	if err != nil {
		return nil, newError(ErrorInvalidRequest, 400, "code_challenge_method is required", err)
	}
	if _, err := pkce.ParseMethod(codeChallengeMethod); err != nil {
		return nil, newError(ErrorInvalidRequest, 400, "code_challenge_method must be S256", err)
	}

	if scopeRaw, ok := params["scope"]; ok {
		scope, err := jsonStringValue(scopeRaw)
		if err != nil {
			return nil, newError(ErrorInvalidRequest, 400, "scope must be a string", err)
		}
		if err := validateScope(scope, client); err != nil {
			return nil, newError(ErrorInvalidRequest, 400, "scope is not valid for this client", err)
		}
	}

	return params, nil
}

func validateScope(scope string, client storage.RegisteredClient) error {
	for _, tok := range strings.Fields(scope) {
		if !client.AllowsScope(tok) {
			return fmt.Errorf("scope %q is not permitted for this client", tok)
		}
	}
	return nil
}

func formParametersToMap(params []FormParameter) (map[string]string, error) {
	out := make(map[string]string, len(params))
	for _, p := range params {
		if _, exists := out[p.Name]; exists {
			return nil, fmt.Errorf("duplicate parameter %q", p.Name)
		}
		out[p.Name] = p.Value
	}
	return out, nil
}

// plainParamsToJSON converts the plain form parameters into the same
// map[string]json.RawMessage shape a verified request object's
// Parameters would have, excluding the client-authentication parameters
// that aren't authorization request parameters.
func plainParamsToJSON(params map[string]string) map[string]json.RawMessage {
	out := make(map[string]json.RawMessage, len(params))
	for k, v := range params {
		if k == "client_assertion" || k == "client_assertion_type" || k == "request" {
			continue
		}
		encoded, _ := json.Marshal(v) // marshaling a string cannot fail
		out[k] = encoded
	}
	return out
}

func jsonString(params map[string]json.RawMessage, key string) (string, error) {
	raw, ok := params[key]
	if !ok {
		return "", fmt.Errorf("missing %q", key)
	}
	return jsonStringValue(raw)
}

func jsonStringValue(raw json.RawMessage) (string, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", fmt.Errorf("must be a string: %w", err)
	}
	return s, nil
}

func (s *Server) audit(ctx context.Context, eventType AuditEventType, clientID fapi.ClientID, outcome AuditOutcome, description string) {
	if s.deps.Audit == nil {
		return
	}
	// Best-effort: PAR is not an issuance event, so a failure to record
	// an audit entry does not fail the request itself.
	_ = s.deps.Audit.Record(ctx, AuditEvent{
		Type:        eventType,
		Time:        s.deps.Clock.Now(),
		ClientID:    clientID,
		Outcome:     outcome,
		Description: description,
	})
}

func (s *Server) parFail(ctx context.Context, clientID fapi.ClientID, err *Error) (PushAuthorizationResult, error) {
	s.audit(ctx, AuditEventPushAuthorizationRequest, clientID, AuditOutcomeFailure, string(err.Code()))
	return PushAuthorizationResult{}, err
}

package server

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/internal/dpop"
	"github.com/idfoundry/fapigo/internal/par"
	"github.com/idfoundry/fapigo/internal/pkce"
	"github.com/idfoundry/fapigo/internal/requestobject"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/storage"
)

// coreAuthorizationParameters are the standard OAuth/OIDC/PKCE
// authorization request parameters this package understands natively —
// excluded from Config.Extensions' unregistered-parameter check, since
// they are not custom parameters.
var coreAuthorizationParameters = map[string]struct{}{
	"response_type": {}, "client_id": {}, "redirect_uri": {}, "scope": {},
	"state": {}, "nonce": {}, "code_challenge": {}, "code_challenge_method": {},
	"login_hint": {},

	// dpop_jkt (RFC 9449 §10) lets a client declare, at authorization
	// time, which DPoP key it intends to bind the eventual tokens to —
	// checked against the actual DPoP proof presented at the token
	// endpoint (server/complete_authorization.go carries it into the
	// stored authorization code; server/token.go enforces the match).
	"dpop_jkt": {},

	// claims (OIDC Core §5.5) lets a client request specific identity
	// claims for the id_token and/or userinfo. This package doesn't
	// parse its structure or honor the per-location/essential detail —
	// it only avoids rejecting the parameter as unregistered. Whatever
	// identity claims a deployment actually returns comes from
	// Dependencies.IdentityClaimsSource, which is free to ignore this
	// parameter's specifics entirely (permitted: OIDC Core §5.5 lets a
	// server return more, or fewer, claims than requested).
	"claims": {},

	// prompt (OIDC Core §3.1.2.1) lets a client request specific
	// re-authentication/consent behavior — most commonly "consent", to
	// force a fresh consent screen when requesting offline_access, so a
	// refresh token is guaranteed to be (re-)issued rather than silently
	// reusing an existing grant. This package doesn't need to act on its
	// value: BeginAuthorization always produces InteractionRequired and
	// there is no "remembered consent" fast path that ever skips
	// rendering consent, so prompt's behavioral requirements are already
	// satisfied unconditionally. It only needs to not be rejected as an
	// unregistered parameter.
	"prompt": {},

	// authorization_details (Rich Authorization Requests, RFC 9396 §5) is
	// excluded here for the same reason as "claims": this package doesn't
	// treat it as an ordinary extension.Definition-backed parameter — it's
	// validated against Config.RAR, a structurally distinct registry for
	// bounded, typed detail-object arrays (see checkExtensions' own use of
	// parseRequestedAuthorizationDetails). Excluding it from
	// Config.Extensions' unregistered-parameter check just keeps that
	// registry from rejecting it outright before RAR-specific validation
	// ever runs.
	"authorization_details": {},

	// response_mode (OAuth Multiple Response Type Encoding Practices;
	// mandatory as "jwt" for a JARM/message-signing client) is not read
	// or validated by this package — whether a response is JARM-encoded
	// is entirely Config.Profile-driven (ProfileFAPISecurityWithMessageSigning
	// always uses it; ProfileFAPISecurity never does), never decided by
	// what a request asks for. It only needs to not be rejected as an
	// unregistered parameter.
	"response_mode": {},
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

	// DPoPProof is the value of the request's DPoP header, if present.
	// A DPoP proof at the PAR endpoint is optional (RFC 9449 §10) — ""
	// means the client didn't send one.
	DPoPProof string

	// PeerCertificate is the TLS client certificate presented on the
	// connection this request arrived on, if any — required when the
	// client authenticates via ClientAuthMethodSelfSignedTLSClientAuth
	// or ClientAuthMethodTLSClientAuth (RFC 8705 §2). An HTTP adapter
	// reads this straight from the connection's own TLS state (e.g.
	// Go's *http.Request.TLS.PeerCertificates[0]); this package never
	// terminates TLS itself.
	PeerCertificate *x509.Certificate
}

// PushAuthorizationResult is returned by a successful
// PushAuthorizationRequest.
type PushAuthorizationResult struct {
	RequestURI RequestURI
	ExpiresIn  time.Duration

	// NextDPoPNonce is a freshly issued DPoP nonce the caller should set
	// as this response's own DPoP-Nonce header, so a subsequent PAR or
	// token request already carries a valid one — issued unconditionally
	// once Dependencies.Nonces is configured, regardless of whether this
	// particular PAR call itself presented a DPoP proof, so a client can
	// pick one up as early as PAR. Always "" when Dependencies.Nonces is
	// nil.
	NextDPoPNonce string
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

	// PAR accepts no endpoint-URL audience at all — only the issuer
	// identifier — see acceptableClientAssertionAudiences's own doc
	// comment for why.
	client, _, authErr := s.authenticateClient(ctx, params, req.PeerCertificate, nil, nil)
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

	validated, dpopErr := s.reconcileParDPoPBinding(ctx, req.DPoPProof, validated)
	if dpopErr != nil {
		return s.parFail(ctx, client.ID(), dpopErr)
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

	var nextNonce string
	if s.deps.Nonces != nil {
		nextNonce, err = s.issueDPoPNonce(ctx, now)
		if err != nil {
			return s.parFail(ctx, client.ID(), newError(ErrorServerError, 500, "failed to issue dpop nonce", err))
		}
	}

	s.audit(ctx, AuditEventPushAuthorizationRequest, client.ID(), AuditOutcomeSuccess, "")
	return PushAuthorizationResult{
		RequestURI:    RequestURI{value: requestURI},
		ExpiresIn:     s.cfg.Limits.PushedRequestLifetime,
		NextDPoPNonce: nextNonce,
	}, nil
}

// authenticateClient authenticates the request's client — via a signed
// client_assertion (RFC 7523) or, for a client registered under
// ClientAuthMethodSelfSignedTLSClientAuth/ClientAuthMethodTLSClientAuth,
// via a plain client_id form parameter plus peerCert (RFC 8705 §2) — and
// resolves the registered client it identifies.
//
// endpoints/mtlsEndpoints list every endpoint URL (and its RFC 8705 §5
// mTLS alias, if any) a client_assertion's "aud" may name, in addition
// to the issuer identifier itself, for the specific physical endpoint
// this call is authenticating a request for; see
// acceptableClientAssertionAudiences's own doc comment for why this
// must be scoped per endpoint rather than accepted for any of them
// interchangeably. Pass nil for both when the calling endpoint accepts
// no endpoint-URL audience at all (PAR — see
// PushAuthorizationRequest's own call site).
func (s *Server) authenticateClient(ctx context.Context, params map[string]string, peerCert *x509.Certificate, endpoints, mtlsEndpoints []fapi.URL) (storage.RegisteredClient, clientassertion.VerifiedAssertion, *Error) {
	switch {
	case params["client_assertion"] != "":
		return s.authenticateClientViaAssertion(ctx, params, endpoints, mtlsEndpoints)
	case params["client_id"] != "":
		return s.authenticateClientViaCertificate(ctx, fapi.ClientID(params["client_id"]), peerCert)
	default:
		return storage.RegisteredClient{}, clientassertion.VerifiedAssertion{},
			newError(ErrorInvalidClient, 401, "client authentication is required", nil)
	}
}

// authenticateClientViaAssertion verifies the request's client_assertion
// and resolves the registered client it identifies. endpoints/mtlsEndpoints
// are authenticateClient's own — see its doc comment.
func (s *Server) authenticateClientViaAssertion(ctx context.Context, params map[string]string, endpoints, mtlsEndpoints []fapi.URL) (storage.RegisteredClient, clientassertion.VerifiedAssertion, *Error) {
	assertionRaw := params["client_assertion"]
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

	// A client registered for certificate-based authentication must not
	// also be authenticatable via a signed assertion — a client's
	// registered method is the sole credential shape that proves its
	// identity, in either direction (see
	// authenticateClientViaCertificate's own symmetric check).
	if client.ClientAuthMethod() != storage.ClientAuthMethodPrivateKeyJWT {
		return storage.RegisteredClient{}, clientassertion.VerifiedAssertion{},
			newError(ErrorInvalidClient, 401, "client is not registered for private_key_jwt client authentication", nil)
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
		ExpectedClientID:  client.ID().String(),
		ExpectedAudiences: s.acceptableClientAssertionAudiences(client, endpoints, mtlsEndpoints),
		Algorithm:         client.ClientAssertionAlgorithm(),
		Now:               s.deps.Clock.Now(),
		MaxLifetime:       s.cfg.Limits.MaxClientAssertionLifetime,
		MaxClockSkew:      s.cfg.Limits.MaxClockSkew,
		Replay:            s.clientAssertionReplayChecker(),
	})
	if err != nil {
		return storage.RegisteredClient{}, clientassertion.VerifiedAssertion{},
			newError(ErrorInvalidClient, 401, "client assertion verification failed", err)
	}

	return client, verified, nil
}

// acceptableClientAssertionAudiences returns the "aud" values this
// server accepts on a client assertion presented to one specific
// endpoint: always the issuer identifier, plus — only the endpoint URLs
// actually named in endpoints, appropriate for the endpoint actually
// authenticating this request — those URLs, and, for a client actually
// registered SenderConstrainMTLS, their RFC 8705 §5 mTLS aliases
// (mtlsEndpoints, matched by position to endpoints). RFC 7523 §3
// sanctions "the token endpoint URL" as "aud" alongside the issuer
// identifier; CIBA Core 1.0 §7.1 separately, explicitly widens this for
// its own backchannel authentication endpoint: "the OP MUST accept its
// Issuer Identifier, Token Endpoint URL, or Backchannel Authentication
// Endpoint URL as values that identify it as an intended audience" —
// confirmed live via the OIDF conformance suite's own
// fapi-ciba-id1/-refresh-token modules, each of which deliberately
// signs "aud" as the token endpoint's URL on a request sent to the
// backchannel authentication endpoint and requires it to succeed.
//
// Deliberately NOT a blanket "any of this server's own endpoint URLs,
// from any endpoint" — confirmed live via
// fapi2-security-profile-final-par-test-{par,token}-endpoint-url-as-audience-fails
// that PAR must reject a client assertion whose "aud" is the PAR
// endpoint's own URL, or the token endpoint's URL: unlike Token and
// BackchannelAuthentication, PAR was never granted a URL-audience
// carve-out by RFC 7523 or CIBA, so PushAuthorizationRequest passes nil
// for both parameters, accepting only the issuer identifier.
func (s *Server) acceptableClientAssertionAudiences(client storage.RegisteredClient, endpoints, mtlsEndpoints []fapi.URL) []string {
	auds := []string{s.cfg.Issuer.String()}
	for _, u := range endpoints {
		if !u.IsZero() {
			auds = append(auds, u.String())
		}
	}
	if client.SenderConstrain() != storage.SenderConstrainMTLS {
		return auds
	}
	for _, u := range mtlsEndpoints {
		if !u.IsZero() {
			auds = append(auds, u.String())
		}
	}
	return auds
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
		tokenClaims, err := s.checkExtensions(ctx, client.ID(), plain, extension.SourcePlainParameter)
		if err != nil {
			return nil, nil, err
		}
		return plain, tokenClaims, nil
	}

	// RFC 9101 §5: a request must not carry both "request" and
	// "request_uri" — they are mutually exclusive ways of conveying the
	// same authorization request. PAR generates its own request_uri as
	// this call's *result*; a client sending one as an *input* parameter
	// here is never meaningful, whether or not "request" is also
	// present (PAR-2.1).
	if _, hasRequestURI := params["request_uri"]; hasRequestURI {
		return nil, nil, newError(ErrorInvalidRequest, 400, "request and request_uri must not both be present", nil)
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
		// FAPI 2.0 Message Signing Final §5.3.1 mandates nbf on a
		// request object; the base FAPI 2.0 Security Profile does not —
		// see requestobject.VerifyPolicy.RequireNotBefore's doc comment.
		RequireNotBefore: s.cfg.Profile == ProfileFAPISecurityWithMessageSigning,
	})
	if err != nil {
		return nil, nil, newError(ErrorInvalidRequestObject, 400, "request object verification failed", err)
	}
	tokenClaims, checkErr := s.checkExtensions(ctx, client.ID(), verified.Parameters, extension.SourceRequestObject)
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
//
// The rejection uses ErrorInvalidRequestObject, not ErrorInvalidRequest,
// when source is extension.SourceRequestObject: the offending parameter
// came from inside a signed request object, not the outer form body, so
// JAR-6.2 is the applicable error family — matching what a client
// embedding e.g. a stray "request_uri" claim inside its own request
// object should see.
//
// Also runs Dependencies.RARRequestPolicy over any "authorization_details"
// the request carries, once it's passed structural validation — see
// RARPolicy's own doc comment for why this exists on top of the
// resource-owner grant step CompleteAuthorization already enforces. On
// success, params[authorizationDetailsParameter] is overwritten in place
// with the policy-narrowed value — params is the same map the caller
// (resolveAuthorizationParameters) goes on to persist as this PAR
// record's own Parameters, so this mutation is what makes the narrowed
// value the one a resource owner is ever shown.
func (s *Server) checkExtensions(ctx context.Context, clientID fapi.ClientID, params map[string]json.RawMessage, source extension.Source) (map[string]json.RawMessage, *Error) {
	values, err := s.cfg.Extensions.Parse(params, coreAuthorizationParameters, source)
	if err != nil {
		code := ErrorInvalidRequest
		if source == extension.SourceRequestObject {
			code = ErrorInvalidRequestObject
		}
		return nil, newError(code, 400, "request contains an unregistered or invalid parameter", err)
	}
	requestedAuthorizationDetails, err := s.parseRequestedAuthorizationDetails(params)
	if err != nil {
		code := ErrorInvalidRequest
		if source == extension.SourceRequestObject {
			code = ErrorInvalidRequestObject
		}
		return nil, newError(code, 400, "authorization_details is invalid", err)
	}
	if len(requestedAuthorizationDetails) > 0 {
		granted, policyErr := s.applyRARPolicy(ctx, clientID, s.deps.RARRequestPolicy, requestedAuthorizationDetails)
		if policyErr != nil {
			return nil, newError(ErrorInvalidAuthorizationDetails, 400, "authorization_details is not permitted for this client", policyErr)
		}
		params[authorizationDetailsParameter] = granted
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

// reconcileParDPoPBinding handles an optional DPoP proof presented
// alongside the pushed authorization request (RFC 9449 §10). A DPoP
// proof at the PAR endpoint is not itself required, but if the client
// sends one, this server:
//   - verifies it (proof of possession of the key, matching htm/htu),
//   - rejects the request outright if an explicit dpop_jkt parameter
//     was also given and doesn't match the proof's key thumbprint, and
//   - otherwise derives an implicit dpop_jkt from the proof's own key
//     when the request carried none, so the resulting authorization
//     code ends up bound to whichever key the client actually
//     demonstrated possession of at PAR time — not just whichever key
//     later shows up at the token endpoint.
//
// The proof's htu is checked against either this endpoint's plain URL
// or its mTLS alias (RFC 8705 §5) — see verifyDPoPAtEitherEndpoint's own
// doc comment for why a DPoP-sender-constrained client may legitimately
// call the alias here too.
func (s *Server) reconcileParDPoPBinding(ctx context.Context, proof string, params map[string]json.RawMessage) (map[string]json.RawMessage, *Error) {
	if proof == "" {
		return params, nil
	}
	verified, err := verifyDPoPAtEitherEndpoint(ctx, dpop.VerifyRequest{
		Proof:        proof,
		Method:       "POST",
		Now:          s.deps.Clock.Now(),
		MaxProofAge:  s.cfg.Limits.MaxDPoPProofAge,
		MaxClockSkew: s.cfg.Limits.MaxClockSkew,
		Replay:       s.dpopReplayChecker(),
	}, s.cfg.Endpoints.PushedAuthorizationRequest, s.cfg.MTLSEndpoints.PushedAuthorizationRequest)
	if err != nil {
		return nil, newError(ErrorInvalidRequest, 400, "DPoP proof verification failed", err)
	}
	if s.deps.Nonces != nil {
		if challenge := s.checkDPoPNonce(ctx, verified.Nonce, s.deps.Clock.Now()); challenge != nil {
			return nil, challenge
		}
	}
	thumbprint := verified.Thumbprint.String()

	if declared, jsonErr := jsonString(params, "dpop_jkt"); jsonErr == nil && declared != "" {
		if declared != thumbprint {
			return nil, newError(ErrorInvalidRequest, 400, "dpop_jkt does not match the DPoP proof presented to the pushed authorization request endpoint", nil)
		}
		return params, nil
	}

	encoded, _ := json.Marshal(thumbprint) // marshaling a string cannot fail
	out := make(map[string]json.RawMessage, len(params)+1)
	for k, v := range params {
		out[k] = v
	}
	out["dpop_jkt"] = encoded
	return out, nil
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
		if k == authorizationDetailsParameter {
			// RFC 9396 §5: a plain "authorization_details" parameter's
			// value is itself JSON array text, unlike every other plain
			// parameter here, which is a bare string re-wrapped as a JSON
			// string claim below. Storing it as a raw message keeps its
			// shape identical to what a signed request object's own
			// "authorization_details" claim decodes to, so
			// parseRequestedAuthorizationDetails/RARRegistry.Parse never
			// need to know which path a request arrived by. Malformed
			// JSON here is caught by RARRegistry.Parse, not here.
			out[k] = json.RawMessage(v)
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

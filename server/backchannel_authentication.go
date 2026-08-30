package server

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/internal/dpop"
	"github.com/idfoundry/fapigo/internal/requestobject"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/storage"
)

// coreBackchannelAuthenticationParameters are the standard CIBA
// backchannel authentication request parameters this package
// understands natively — excluded from Config.Extensions'
// unregistered-parameter check, mirroring coreAuthorizationParameters
// for PAR.
var coreBackchannelAuthenticationParameters = map[string]struct{}{
	"scope": {}, "login_hint": {}, "login_hint_token": {}, "id_token_hint": {},
	"acr_values": {}, "binding_message": {}, "client_notification_token": {},
	"requested_expiry": {}, "dpop_jkt": {},

	// claims (OIDC Core §5.5) mirrors coreAuthorizationParameters'
	// handling of the same parameter for PAR — see
	// BeginBackchannelAuthentication's own use of parseRequestedClaimNames.
	"claims": {},

	// authorization_details (RFC 9396 §5) mirrors coreAuthorizationParameters'
	// handling of the same parameter for PAR — see checkBackchannelExtensions'
	// own use of parseRequestedAuthorizationDetails.
	"authorization_details": {},
}

// BackchannelAuthenticationAction is a closed sum type returned by
// BeginBackchannelAuthentication, mirroring AuthorizationAction for the
// browser-based flow.
type BackchannelAuthenticationAction interface {
	backchannelAuthenticationAction()
}

// BackchannelInteractionRequired means the embedding application must
// authenticate (and obtain consent from) the end user out-of-band
// before this request can be decided. Handle must be passed back to
// CompleteBackchannelAuthentication once that concludes.
type BackchannelInteractionRequired struct {
	Handle    BackchannelAuthenticationHandle
	AuthReqID AuthReqID
	ExpiresIn time.Duration

	// Interval is the minimum time the client must wait between token
	// endpoint polls (CIBA §10.3's "interval").
	Interval time.Duration

	Interaction BackchannelInteractionRequest
}

func (BackchannelInteractionRequired) backchannelAuthenticationAction() {}

// BackchannelAuthenticationLocalError means the caller must report an
// error rather than issue an auth_req_id — CIBA has no redirect to
// carry an error in, so (unlike LocalErrorResponse's browser-flow
// contrast with a redirect) this is simply this method's one error
// shape.
type BackchannelAuthenticationLocalError struct {
	Error *Error
}

func (BackchannelAuthenticationLocalError) backchannelAuthenticationAction() {}

// BeginBackchannelAuthenticationRequest is the input to
// Server.BeginBackchannelAuthentication.
type BeginBackchannelAuthenticationRequest struct {
	HTTP FormRequest

	// DPoPProof is the value of the request's DPoP header, if present.
	// Optional, mirroring PushAuthorizationRequest.DPoPProof — see
	// reconcileBackchannelDPoPBinding.
	DPoPProof string

	// PeerCertificate is the TLS client certificate presented on the
	// connection this request arrived on, if any — required when the
	// client authenticates via ClientAuthMethodSelfSignedTLSClientAuth
	// or ClientAuthMethodTLSClientAuth (RFC 8705 §2), mirroring
	// PushAuthorizationRequest.PeerCertificate.
	PeerCertificate *x509.Certificate
}

// BeginBackchannelAuthentication authenticates the client, verifies its
// signed backchannel authentication request (FAPI-CIBA always requires
// one — there is no plain-parameter path, unlike PAR), validates it
// against the client's registration, and persists it for the
// embedder's own out-of-band authentication component to later decide
// via CompleteBackchannelAuthentication.
func (s *Server) BeginBackchannelAuthentication(ctx context.Context, req BeginBackchannelAuthenticationRequest) (BackchannelAuthenticationAction, error) {
	if s.cfg.Endpoints.BackchannelAuthentication.IsZero() {
		return s.backchannelBeginFail(ctx, "", newError(ErrorServerError, 500, "backchannel authentication is not configured", nil)), nil
	}

	params, err := formParametersToMap(req.HTTP.Parameters)
	if err != nil {
		return s.backchannelBeginFail(ctx, "", newError(ErrorInvalidRequest, 400, "the request contains a duplicated parameter", err)), nil
	}

	// CIBA Core 1.0 §7.1 explicitly widens the backchannel authentication
	// endpoint's own accepted audiences beyond just its own URL: "the OP
	// MUST accept its Issuer Identifier, Token Endpoint URL, or
	// Backchannel Authentication Endpoint URL" — confirmed live via the
	// OIDF conformance suite's own fapi-ciba-id1/-refresh-token modules,
	// which deliberately sign "aud" as the token endpoint's URL here.
	client, _, authErr := s.authenticateClient(ctx, params, req.PeerCertificate,
		[]fapi.URL{s.cfg.Endpoints.BackchannelAuthentication, s.cfg.Endpoints.Token},
		[]fapi.URL{s.cfg.MTLSEndpoints.BackchannelAuthentication, s.cfg.MTLSEndpoints.Token})
	if authErr != nil {
		return s.backchannelBeginFail(ctx, "", authErr), nil
	}

	verified, resolveErr := s.resolveBackchannelAuthenticationParameters(ctx, params, client)
	if resolveErr != nil {
		return s.backchannelBeginFail(ctx, client.ID(), resolveErr), nil
	}

	validated, validateErr := s.validateBackchannelAuthenticationParameters(verified, client)
	if validateErr != nil {
		return s.backchannelBeginFail(ctx, client.ID(), validateErr), nil
	}

	dpopJKT, dpopErr := s.reconcileBackchannelDPoPBinding(ctx, req.DPoPProof)
	if dpopErr != nil {
		return s.backchannelBeginFail(ctx, client.ID(), dpopErr), nil
	}

	authReqIDRaw, err := generateAuthReqID(s.deps.Random)
	if err != nil {
		return s.backchannelBeginFail(ctx, client.ID(), newError(ErrorServerError, 500, "failed to generate auth_req_id", err)), nil
	}
	handleRaw, err := generateBackchannelAuthenticationHandle(s.deps.Random)
	if err != nil {
		return s.backchannelBeginFail(ctx, client.ID(), newError(ErrorServerError, 500, "failed to generate backchannel authentication handle", err)), nil
	}

	now := s.deps.Clock.Now()
	lifetime := s.backchannelAuthenticationLifetime(validated.params)
	expiresAt := now.Add(lifetime)
	idTokenClaims, userinfoClaims := parseRequestedClaimNames(validated.params["claims"])

	// deliveryMode/notificationToken mirror client's own registered
	// BackchannelTokenDeliveryMode exactly — validateBackchannelAuthenticationParameters
	// already enforced that a "ping" client's request carries
	// client_notification_token and a "poll" client's doesn't, so
	// there's nothing left to branch on here beyond which value to
	// persist.
	deliveryMode := "poll"
	var notificationToken fapi.Secret
	var authReqIDForNotification string
	if client.BackchannelTokenDeliveryMode() == storage.BackchannelTokenDeliveryModePing {
		deliveryMode = "ping"
		tokenValue, _ := jsonStringValue(validated.params["client_notification_token"])
		notificationToken = fapi.NewSecret(tokenValue)
		// Retained in the clear (unlike AuthReqIDHash) only under ping —
		// CIBA §10.2 requires the notification body to carry this value
		// back later, so it can't be digest-only here, the same
		// exception ClientNotificationToken's own doc comment explains.
		authReqIDForNotification = authReqIDRaw
	}

	if err := s.deps.Backchannel.CreateBackchannelAuthentication(ctx, storage.NewBackchannelAuthentication{
		AuthReqIDHash:           sha256.Sum256([]byte(authReqIDRaw)),
		AuthReqID:               authReqIDForNotification,
		HandleHash:              sha256.Sum256([]byte(handleRaw)),
		ClientID:                client.ID(),
		Parameters:              validated.params,
		TokenClaims:             validated.tokenClaims,
		RequestedIDTokenClaims:  idTokenClaims,
		RequestedUserinfoClaims: userinfoClaims,
		DeliveryMode:            deliveryMode,
		ClientNotificationToken: notificationToken,
		DPoPJKT:                 dpopJKT,
		PollInterval:            s.cfg.Limits.BackchannelAuthenticationPollInterval,
		ExpiresAt:               expiresAt,
	}); err != nil {
		return s.backchannelBeginFail(ctx, client.ID(), newError(ErrorServerError, 500, "failed to persist backchannel authentication request", err)), nil
	}

	action := BackchannelInteractionRequired{
		Handle:      BackchannelAuthenticationHandle{value: handleRaw},
		AuthReqID:   AuthReqID{value: authReqIDRaw},
		ExpiresIn:   lifetime,
		Interval:    s.cfg.Limits.BackchannelAuthenticationPollInterval,
		Interaction: s.backchannelInteractionRequestFrom(client.ID(), validated.params),
	}
	s.audit(ctx, AuditEventBeginBackchannelAuthentication, client.ID(), AuditOutcomeSuccess, "")
	return action, nil
}

// verifiedBackchannelRequest is a backchannel authentication request's
// parameters, once its signature has been verified — the CIBA
// counterpart of the (map[string]json.RawMessage, map[string]json.RawMessage)
// pair resolveAuthorizationParameters returns for PAR.
type verifiedBackchannelRequest struct {
	params      map[string]json.RawMessage
	tokenClaims map[string]json.RawMessage
}

// resolveBackchannelAuthenticationParameters verifies the request's
// signed backchannel authentication request object — FAPI-CIBA always
// requires one (confirmed by the OIDF FAPI-CIBA-ID1 conformance suite's
// own EnsureBackchannelAuthorizationRequestWithoutRequestFails negative
// test), unlike PAR's request object, whose signing is profile-dependent.
//
// Every rejection below uses ErrorInvalidRequest, never
// ErrorInvalidRequestObject: unlike PAR/authorize, where a malformed
// request object gets RFC 9101's own JAR-6.2 error family (see
// checkExtensions' own doc comment), CIBA Core 1.0 §13 defines no
// separate "invalid_request_object" error at all — every one of its
// request-object-related negative tests
// (AbstractFAPICIBAID1EnsureSendingInvalidBackchannelAuthorizationRequest,
// confirmed by disassembling its own checkErrorFromBackchannelAuthorizationRequestResponse)
// uniformly expects plain invalid_request, regardless of which claim
// is missing or malformed.
func (s *Server) resolveBackchannelAuthenticationParameters(ctx context.Context, params map[string]string, client storage.RegisteredClient) (verifiedBackchannelRequest, *Error) {
	requestParam, ok := params["request"]
	if !ok || requestParam == "" {
		return verifiedBackchannelRequest{}, newError(ErrorInvalidRequest, 400, "a signed backchannel authentication request is required", nil)
	}

	alg, permitted := client.BackchannelAuthenticationRequestAlgorithm()
	if !permitted {
		return verifiedBackchannelRequest{}, newError(ErrorInvalidRequest, 400, "client is not permitted to use CIBA", nil)
	}
	if !s.cfg.Algorithms.BackchannelAuthenticationRequest.Contains(alg) {
		return verifiedBackchannelRequest{}, newError(ErrorInvalidRequest, 400, "backchannel authentication request algorithm is not permitted", nil)
	}

	obj, err := requestobject.Parse(requestParam)
	if err != nil {
		return verifiedBackchannelRequest{}, newError(ErrorInvalidRequest, 400, "malformed backchannel authentication request", err)
	}

	pub, err := s.resolveClientKey(ctx, client.ID(), keys.BackchannelAuthenticationRequestVerification, alg, obj.KeyID())
	if err != nil {
		return verifiedBackchannelRequest{}, newError(ErrorInvalidRequest, 400, "no matching client key", err)
	}

	verified, err := obj.Verify(ctx, pub, requestobject.VerifyPolicy{
		ExpectedClientID: client.ID().String(),
		ExpectedAudience: s.cfg.Issuer.String(),
		Algorithm:        alg,
		Now:              s.deps.Clock.Now(),
		MaxLifetime:      s.cfg.Limits.MaxBackchannelAuthenticationRequestLifetime,
		MaxClockSkew:     s.cfg.Limits.MaxClockSkew,
		Replay:           s.backchannelAuthenticationRequestReplayChecker(),
		// Unlike PAR's request object (single-use via its own
		// request_uri wrapper — see requestobject.VerifyPolicy.Replay's
		// own doc comment for why nbf/jti are optional there), a CIBA
		// backchannel authentication request has no such wrapper of its
		// own, so the OIDF FAPI-CIBA-ID1 conformance suite mandates all
		// three unconditionally (nbf/jti already; iat confirmed by its
		// own EnsureRequestObjectMissingIatFails negative test).
		RequireNotBefore: true,
		RequireJTI:       true,
		RequireIssuedAt:  true,
	})
	if err != nil {
		return verifiedBackchannelRequest{}, newError(ErrorInvalidRequest, 400, "backchannel authentication request verification failed", err)
	}
	tokenClaims, checkErr := s.checkBackchannelExtensions(ctx, client.ID(), verified.Parameters)
	if checkErr != nil {
		return verifiedBackchannelRequest{}, checkErr
	}
	return verifiedBackchannelRequest{params: verified.Parameters, tokenClaims: tokenClaims}, nil
}

// checkBackchannelExtensions is checkExtensions' CIBA counterpart —
// same Config.Extensions registry, its own core-parameter allow-list,
// and the same Dependencies.CIBARARPolicy narrowing (see
// checkExtensions' own doc comment for the shared mechanism — params is
// mutated in place the same way).
func (s *Server) checkBackchannelExtensions(ctx context.Context, clientID fapi.ClientID, params map[string]json.RawMessage) (map[string]json.RawMessage, *Error) {
	values, err := s.cfg.Extensions.Parse(params, coreBackchannelAuthenticationParameters, extension.SourceRequestObject)
	if err != nil {
		return nil, newError(ErrorInvalidRequest, 400, "request contains an unregistered or invalid parameter", err)
	}
	requestedAuthorizationDetails, err := s.parseRequestedAuthorizationDetails(params)
	if err != nil {
		return nil, newError(ErrorInvalidRequest, 400, "authorization_details is invalid", err)
	}
	if len(requestedAuthorizationDetails) > 0 {
		granted, policyErr := s.applyRARPolicy(ctx, clientID, s.deps.CIBARARPolicy, requestedAuthorizationDetails)
		if policyErr != nil {
			return nil, newError(ErrorInvalidAuthorizationDetails, 400, "authorization_details is not permitted for this client", policyErr)
		}
		params[authorizationDetailsParameter] = granted
	}
	return extension.AsParameters(values, s.cfg.Extensions.Definitions()...), nil
}

// validateBackchannelAuthenticationParameters checks the CIBA-mandated
// parameters (scope, exactly one identity hint) against client, plus
// client_notification_token (see validateClientNotificationToken) and
// binding_message.
func (s *Server) validateBackchannelAuthenticationParameters(verified verifiedBackchannelRequest, client storage.RegisteredClient) (verifiedBackchannelRequest, *Error) {
	params := verified.params

	scopeRaw, ok := params["scope"]
	if !ok {
		return verifiedBackchannelRequest{}, newError(ErrorInvalidRequest, 400, "scope is required", nil)
	}
	scope, err := jsonStringValue(scopeRaw)
	if err != nil {
		return verifiedBackchannelRequest{}, newError(ErrorInvalidRequest, 400, "scope must be a string", err)
	}
	if err := validateScope(scope, client); err != nil {
		return verifiedBackchannelRequest{}, newError(ErrorInvalidRequest, 400, "scope is not valid for this client", err)
	}

	hints := 0
	for _, name := range [...]string{"login_hint", "login_hint_token", "id_token_hint"} {
		if _, ok := params[name]; ok {
			hints++
		}
	}
	if hints != 1 {
		return verifiedBackchannelRequest{}, newError(ErrorInvalidRequest, 400, "exactly one of login_hint, login_hint_token, or id_token_hint is required", nil)
	}

	if validateErr := validateClientNotificationToken(params, client); validateErr != nil {
		return verifiedBackchannelRequest{}, validateErr
	}

	if raw, ok := params["binding_message"]; ok {
		bindingMessage, err := jsonStringValue(raw)
		if err != nil {
			return verifiedBackchannelRequest{}, newError(ErrorInvalidRequest, 400, "binding_message must be a string", err)
		}
		if !isAcceptableBindingMessage(bindingMessage) {
			return verifiedBackchannelRequest{}, newError(ErrorInvalidBindingMessage, 400, "binding_message is not acceptable", nil)
		}
	}

	return verified, nil
}

// validateClientNotificationToken checks client_notification_token's
// presence against exactly what client's own registered
// BackchannelTokenDeliveryMode requires (CIBA §7.1: required for
// ping/push, meaningless for poll) — push itself is never supported,
// since storage.BackchannelTokenDeliveryMode has no value for it.
func validateClientNotificationToken(params map[string]json.RawMessage, client storage.RegisteredClient) *Error {
	notificationTokenRaw, hasNotificationToken := params["client_notification_token"]
	switch client.BackchannelTokenDeliveryMode() {
	case storage.BackchannelTokenDeliveryModePoll:
		if hasNotificationToken {
			return newError(ErrorInvalidRequest, 400, "client_notification_token is not permitted for a client registered for poll delivery", nil)
		}
	case storage.BackchannelTokenDeliveryModePing:
		if !hasNotificationToken {
			return newError(ErrorInvalidRequest, 400, "client_notification_token is required for a client registered for ping delivery", nil)
		}
		if _, err := jsonStringValue(notificationTokenRaw); err != nil {
			return newError(ErrorInvalidRequest, 400, "client_notification_token must be a string", err)
		}
	}
	return nil
}

// maxBindingMessageLength bounds a binding_message to something a real
// display surface (a push notification, an SMS, a small screen) can
// show in full at a glance — CIBA §7.1's own examples are short codes
// like "W4SCT"; nothing about the protocol calls for a message that
// can't be read in one look. Chosen generously above ordinary usage,
// not tuned to any specific test input.
const maxBindingMessageLength = 100

// isAcceptableBindingMessage reports whether msg is a binding_message
// (CIBA §7.1) this server can display to an end user faithfully and in
// full — the short, human-scannable identifier CIBA's transaction-
// interlocking model depends on, not an arbitrary string. CIBA §13
// explicitly gives an AS invalid_binding_message to reject one it
// considers unacceptable, rather than accepting whatever a client sends
// and hoping its own display surface can render it. Only length and
// control/line-separator characters are checked — a display surface
// can't safely render a value spanning multiple lines or embedding
// control codes, but ordinary punctuation, emoji, and non-Latin scripts
// are all fine and remain accepted.
func isAcceptableBindingMessage(msg string) bool {
	if utf8.RuneCountInString(msg) > maxBindingMessageLength {
		return false
	}
	for _, r := range msg {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			return false
		}
	}
	return true
}

// reconcileBackchannelDPoPBinding is reconcileParDPoPBinding's CIBA
// counterpart: a DPoP proof at the backchannel authentication endpoint
// is optional, exactly like PAR — see Open Question 1 in this feature's
// design plan for why this mirrors PAR rather than the token endpoint's
// always-required proof.
func (s *Server) reconcileBackchannelDPoPBinding(ctx context.Context, proof string) (string, *Error) {
	if proof == "" {
		return "", nil
	}
	endpoint := s.cfg.Endpoints.BackchannelAuthentication.URL()
	verified, err := dpop.Verify(ctx, dpop.VerifyRequest{
		Proof:        proof,
		Method:       "POST",
		URL:          &endpoint,
		Now:          s.deps.Clock.Now(),
		MaxProofAge:  s.cfg.Limits.MaxDPoPProofAge,
		MaxClockSkew: s.cfg.Limits.MaxClockSkew,
		Replay:       s.dpopReplayChecker(),
	})
	if err != nil {
		return "", newError(ErrorInvalidRequest, 400, "DPoP proof verification failed", err)
	}
	if s.deps.Nonces != nil {
		if challenge := s.checkDPoPNonce(ctx, verified.Nonce, s.deps.Clock.Now()); challenge != nil {
			return "", challenge
		}
	}
	return verified.Thumbprint.String(), nil
}

// backchannelAuthenticationLifetime returns how long a newly created
// request should remain pollable: the client's own requested_expiry
// (CIBA §7.1), clamped to Limits.BackchannelAuthenticationRequestLifetime,
// or that configured default if the client didn't send one (or sent an
// unparseable value).
func (s *Server) backchannelAuthenticationLifetime(params map[string]json.RawMessage) time.Duration {
	max := s.cfg.Limits.BackchannelAuthenticationRequestLifetime
	raw, ok := params["requested_expiry"]
	if !ok {
		return max
	}
	seconds, ok := parseRequestedExpiry(raw)
	if !ok || seconds <= 0 {
		return max
	}
	requested := time.Duration(seconds) * time.Second
	if requested > max {
		return max
	}
	return requested
}

// parseRequestedExpiry accepts both forms the OIDF FAPI-CIBA-ID1
// conformance suite's own tests exercise: a JSON number, or (its own
// EnsureRequestedExpiryAsStringSucceeds test) a numeric string.
func parseRequestedExpiry(raw json.RawMessage) (int64, bool) {
	var n int64
	if err := json.Unmarshal(raw, &n); err == nil {
		return n, true
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if n, err := strconv.ParseInt(s, 10, 64); err == nil {
			return n, true
		}
	}
	return 0, false
}

func (s *Server) backchannelInteractionRequestFrom(clientID fapi.ClientID, params map[string]json.RawMessage) BackchannelInteractionRequest {
	var scopes []string
	if scope, err := jsonString(params, "scope"); err == nil && scope != "" {
		scopes = strings.Fields(scope)
	}

	var hints BackchannelAuthenticationHints
	if raw, ok := params["login_hint"]; ok {
		if v, err := jsonStringValue(raw); err == nil {
			hints.LoginHint = LoginHint(v)
		}
	}
	if raw, ok := params["login_hint_token"]; ok {
		if v, err := jsonStringValue(raw); err == nil {
			hints.LoginHintToken = v
		}
	}
	if raw, ok := params["id_token_hint"]; ok {
		if v, err := jsonStringValue(raw); err == nil {
			hints.IDTokenHint = v
		}
	}

	var acrValues []string
	if v, err := jsonString(params, "acr_values"); err == nil && v != "" {
		acrValues = strings.Fields(v)
	}
	bindingMessage, _ := jsonString(params, "binding_message")

	return BackchannelInteractionRequest{
		ClientID: clientID, Scope: scopes, Hints: hints,
		ACRValues: acrValues, BindingMessage: bindingMessage,
		AuthorizationDetails: rarValuesFromStoredParameters(s.cfg.RAR, params),
	}
}

func (s *Server) backchannelBeginFail(ctx context.Context, clientID fapi.ClientID, err *Error) BackchannelAuthenticationAction {
	s.audit(ctx, AuditEventBeginBackchannelAuthentication, clientID, AuditOutcomeFailure, string(err.Code()))
	return BackchannelAuthenticationLocalError{Error: err}
}

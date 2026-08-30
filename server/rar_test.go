package server_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/internal/token"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// testPaymentDetail is a minimal Rich Authorization Requests (RFC 9396)
// detail type used across this file's tests — a generic transaction
// approval, not modeled on any real third-party scheme.
type testPaymentDetail struct {
	Type    string   `json:"type"`
	Actions []string `json:"actions"`
	Amount  string   `json:"amount,omitempty"`
}

var paymentRARDef = extension.RARDefinition[testPaymentDetail]{
	Type: "payment", MaxObjects: 5, MaxBytesPerObject: 1024,
}

func newTestRARRegistry(t *testing.T) *extension.RARRegistry {
	t.Helper()
	registry, err := extension.NewRARRegistry(4096, 4, paymentRARDef)
	if err != nil {
		t.Fatalf("NewRARRegistry: %v", err)
	}
	return registry
}

// newHarnessWithRAR mirrors newHarnessWithExtensions/newHarnessWithBackchannel,
// combined: a harness with Config.RAR set, and CIBA fully wired (a real
// memstore.BackchannelAuthenticationStore, matching endpoint/algorithm/
// limits), so the same harness can exercise both PAR and CIBA RAR flows.
func newHarnessWithRAR(t *testing.T, profile server.Profile, registry *extension.RARRegistry) harness {
	t.Helper()
	now := time.Now()
	key := generateKey(t)
	serverKey := generateKey(t)

	client, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID:                       testClientID,
		RedirectURIs:             []fapi.RegisteredRedirectURI{testRedirectURI},
		ClientAssertionAlgorithm: fapi.ES256,
		RequestObjectAlgorithm:   fapi.ES256,
		AllowedScopes:            []string{"openid", "accounts"},
		BackchannelAuthenticationRequestAlgorithm: fapi.ES256,
	})
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}
	issuer, err := fapi.ParseIssuerURL(testIssuer)
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}
	backchannelEndpoint, err := fapi.ParseEndpointURL(testBackchannelAuthenticationEndpoint)
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	endpoints := testEndpoints(t)
	endpoints.BackchannelAuthentication = backchannelEndpoint

	cfg := server.Config{
		Issuer:    issuer,
		Endpoints: endpoints,
		Profile:   profile,
		Algorithms: server.AlgorithmPolicy{
			ClientAssertion:                  server.AlgorithmSet{fapi.ES256},
			RequestObject:                    server.AlgorithmSet{fapi.ES256},
			JARM:                             fapi.ES256,
			IDToken:                          fapi.ES256,
			BackchannelAuthenticationRequest: server.AlgorithmSet{fapi.ES256},
		},
		Limits: server.Limits{
			PushedRequestLifetime:                       90 * time.Second,
			MaxClientAssertionLifetime:                  time.Minute,
			MaxRequestObjectLifetime:                    time.Minute,
			InteractionLifetime:                         5 * time.Minute,
			AuthorizationCodeLifetime:                   time.Minute,
			JARMResponseLifetime:                        time.Minute,
			AccessTokenLifetime:                         5 * time.Minute,
			IDTokenLifetime:                             5 * time.Minute,
			RefreshTokenLifetime:                        5 * time.Minute,
			MaxDPoPProofAge:                             time.Minute,
			MaxClockSkew:                                5 * time.Second,
			BackchannelAuthenticationRequestLifetime:    2 * time.Minute,
			MaxBackchannelAuthenticationRequestLifetime: time.Minute,
			BackchannelAuthenticationPollInterval:       time.Millisecond,
		},
		Assurance: server.AssuranceDevelopment,
		RAR:       registry,
	}
	serverKeyManager := &fakeKeyManager{key: serverKey, keyID: "as-key-1"}
	deps := server.Dependencies{
		Clients:      &fakeClientRepository{clients: map[fapi.ClientID]storage.RegisteredClient{testClientID: client}},
		Transactions: &fakeTransactionStore{},
		Grants:       &fakeGrantStore{},
		Replay:       &fakeReplayStore{},
		ClientKeys: &fakeClientKeySource{keysByClient: map[fapi.ClientID][]keys.VerificationKey{
			testClientID: {{Algorithm: fapi.ES256, PublicKey: &key.PublicKey}},
		}},
		Keys:                serverKeyManager,
		AccessTokens:        server.JWTAccessTokens{Keys: serverKeyManager, Algorithm: fapi.ES256},
		Revocation:          server.NoRevocation{},
		Clock:               fixedClock{now: now},
		Random:              rand.Reader,
		Backchannel:         memstore.NewBackchannelAuthenticationStore(),
		BackchannelNotifier: server.NoBackchannelNotifications{},
	}
	srv, err := server.New(cfg, deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return harness{server: srv, key: key, serverKey: serverKey, now: now}
}

func rarSubjectAndAuthCtx(t *testing.T, now time.Time) (server.AuthenticatedSubject, server.AuthenticationContext) {
	t.Helper()
	subjectID, err := server.NewSubjectID("user-1")
	if err != nil {
		t.Fatalf("NewSubjectID: %v", err)
	}
	subject, err := server.NewAuthenticatedSubject(subjectID)
	if err != nil {
		t.Fatalf("NewAuthenticatedSubject: %v", err)
	}
	authCtx, err := server.NewAuthenticationContext(now, "", nil)
	if err != nil {
		t.Fatalf("NewAuthenticationContext: %v", err)
	}
	return subject, authCtx
}

// authorizationDetailsAccessTokenClaim decodes and returns the raw
// "authorization_details" claim from a validated access token, failing
// the test if it's absent.
func authorizationDetailsAccessTokenClaim(t *testing.T, raw string, publicKey any) json.RawMessage {
	t.Helper()
	parsed, err := token.ParseAccessToken(raw)
	if err != nil {
		t.Fatalf("ParseAccessToken: %v", err)
	}
	validated, err := parsed.Validate(publicKey, token.AccessTokenValidatePolicy{
		ExpectedIssuer: testIssuer, ExpectedAudience: testIssuer,
		Algorithm: fapi.ES256, Now: time.Now(), MaxLifetime: 10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Validate access token: %v", err)
	}
	claim, ok := validated.Parameters["authorization_details"]
	if !ok {
		t.Fatalf("access token claims are missing authorization_details; got %v", validated.Parameters)
	}
	return claim
}

// --- PAR (plain-parameter path) -----------------------------------------

func TestPushAuthorizationRequestPlainAuthorizationDetailsFlow(t *testing.T) {
	h := newHarnessWithRAR(t, server.ProfileFAPISecurity, newTestRARRegistry(t))

	requested := `[{"type":"payment","actions":["approve"],"amount":"SGD 500.00"},{"type":"payment","actions":["approve"],"amount":"SGD 10.00"}]`
	pushResult, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: plainFormParameters(t, h.clientAssertion(t), map[string]string{
			"authorization_details": requested,
		})},
	})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}

	action, err := h.server.BeginAuthorization(context.Background(), server.BeginAuthorizationRequest{
		RequestURI: pushResult.RequestURI.String(), ClientID: testClientID,
	})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	interaction, ok := action.(server.InteractionRequired)
	if !ok {
		t.Fatalf("action = %T, want server.InteractionRequired", action)
	}
	details, err := extension.RARGet(interaction.Interaction.AuthorizationDetails, paymentRARDef)
	if err != nil {
		t.Fatalf("RARGet: %v", err)
	}
	if len(details) != 2 {
		t.Fatalf("RARGet returned %d objects, want 2", len(details))
	}

	// The resource owner approves only the smaller payment — a genuine
	// narrowing, mirroring how a granted scope may be a subset of what
	// was requested.
	granted := []json.RawMessage{mustMarshal(t, details[1].Fields)}
	subject, authCtx := rarSubjectAndAuthCtx(t, h.now)
	result, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
		Handle: interaction.Handle,
		Result: server.Authorize(subject, authCtx, server.GrantedAuthorization{
			Scope: []string{"openid", "accounts"}, AuthorizationDetails: granted,
		}),
	})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	redirect, ok := result.(server.AuthorizationRedirect)
	if !ok {
		t.Fatalf("result = %T, want server.AuthorizationRedirect", result)
	}
	dest := redirect.Destination().URL()
	code := dest.Query().Get("code")
	if code == "" {
		t.Fatalf("redirect missing code parameter")
	}

	dpopKey := generateKey(t)
	exchangeResult, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:      server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
		DPoPProof: createDPoPProof(t, dpopKey, h.now),
	})
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}

	// The token response echoes exactly the granted (narrowed) array,
	// per RFC 9396 §5.
	var responseEchoed []testPaymentDetail
	if err := json.Unmarshal(exchangeResult.AuthorizationDetails, &responseEchoed); err != nil {
		t.Fatalf("unmarshal TokenResult.AuthorizationDetails: %v", err)
	}
	if len(responseEchoed) != 1 || responseEchoed[0].Amount != "SGD 10.00" {
		t.Fatalf("TokenResult.AuthorizationDetails = %s, want the narrowed SGD 10.00 payment only", exchangeResult.AuthorizationDetails)
	}

	claim := authorizationDetailsAccessTokenClaim(t, exchangeResult.AccessToken.Reveal(), &h.serverKey.PublicKey)
	var claimed []testPaymentDetail
	if err := json.Unmarshal(claim, &claimed); err != nil {
		t.Fatalf("unmarshal access token authorization_details claim: %v", err)
	}
	if len(claimed) != 1 || claimed[0].Amount != "SGD 10.00" {
		t.Fatalf("access token authorization_details claim = %s, want the narrowed SGD 10.00 payment only", claim)
	}
}

func TestCompleteAuthorizationRejectsUnrequestedAuthorizationDetails(t *testing.T) {
	h := newHarnessWithRAR(t, server.ProfileFAPISecurity, newTestRARRegistry(t))

	pushResult, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: plainFormParameters(t, h.clientAssertion(t), map[string]string{
			"authorization_details": `[{"type":"payment","actions":["approve"],"amount":"SGD 10.00"}]`,
		})},
	})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
	action, err := h.server.BeginAuthorization(context.Background(), server.BeginAuthorizationRequest{
		RequestURI: pushResult.RequestURI.String(), ClientID: testClientID,
	})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	interaction := action.(server.InteractionRequired)

	// The embedding application (or a compromised consent step) tries to
	// grant a payment amount that was never requested — this must be
	// rejected, not silently widened into the issued token.
	subject, authCtx := rarSubjectAndAuthCtx(t, h.now)
	result, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
		Handle: interaction.Handle,
		Result: server.Authorize(subject, authCtx, server.GrantedAuthorization{
			Scope: []string{"openid", "accounts"},
			AuthorizationDetails: []json.RawMessage{
				json.RawMessage(`{"type":"payment","actions":["approve"],"amount":"SGD 999999.00"}`),
			},
		}),
	})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	localErr, ok := result.(server.AuthorizationLocalError)
	if !ok {
		t.Fatalf("result = %T, want server.AuthorizationLocalError", result)
	}
	if localErr.Error.Code() != server.ErrorInvalidRequest {
		t.Fatalf("Error.Code() = %v, want %v", localErr.Error.Code(), server.ErrorInvalidRequest)
	}
}

func TestPushAuthorizationRequestRejectsAuthorizationDetailsWithoutRARConfigured(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)

	_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: plainFormParameters(t, h.clientAssertion(t), map[string]string{
			"authorization_details": `[{"type":"payment","actions":["approve"]}]`,
		})},
	})
	if err == nil {
		t.Fatalf("PushAuthorizationRequest = nil error, want error (Config.RAR is not configured)")
	}
	if serverErrorCode(t, err) != server.ErrorInvalidRequest {
		t.Fatalf("error code = %v, want %v", serverErrorCode(t, err), server.ErrorInvalidRequest)
	}
}

func TestPushAuthorizationRequestRejectsMalformedAuthorizationDetails(t *testing.T) {
	h := newHarnessWithRAR(t, server.ProfileFAPISecurity, newTestRARRegistry(t))

	_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: plainFormParameters(t, h.clientAssertion(t), map[string]string{
			// A JSON object, not an array — RFC 9396 §5 requires an array
			// of detail objects.
			"authorization_details": `{"type":"payment","actions":["approve"]}`,
		})},
	})
	if err == nil {
		t.Fatalf("PushAuthorizationRequest = nil error, want error (authorization_details must be a JSON array)")
	}
	if serverErrorCode(t, err) != server.ErrorInvalidRequest {
		t.Fatalf("error code = %v, want %v", serverErrorCode(t, err), server.ErrorInvalidRequest)
	}
}

func TestBeginAuthorizationAuthorizationDetailsAbsentWhenNotRequested(t *testing.T) {
	h := newHarnessWithRAR(t, server.ProfileFAPISecurity, newTestRARRegistry(t))
	action := pushAndBegin(t, h, nil)
	interaction, ok := action.(server.InteractionRequired)
	if !ok {
		t.Fatalf("action = %T, want server.InteractionRequired", action)
	}
	details, err := extension.RARGet(interaction.Interaction.AuthorizationDetails, paymentRARDef)
	if err != nil {
		t.Fatalf("RARGet: %v", err)
	}
	if len(details) != 0 {
		t.Fatalf("RARGet returned %d objects, want 0 (request carried no authorization_details)", len(details))
	}
}

func TestCompleteAuthorizationRejectsAuthorizationDetailsGrantedButNeverRequested(t *testing.T) {
	h := newHarnessWithRAR(t, server.ProfileFAPISecurity, newTestRARRegistry(t))
	// The pushed request carries no authorization_details at all.
	action := pushAndBegin(t, h, nil)
	interaction := action.(server.InteractionRequired)

	subject, authCtx := rarSubjectAndAuthCtx(t, h.now)
	result, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
		Handle: interaction.Handle,
		Result: server.Authorize(subject, authCtx, server.GrantedAuthorization{
			Scope: []string{"openid", "accounts"},
			AuthorizationDetails: []json.RawMessage{
				json.RawMessage(`{"type":"payment","actions":["approve"],"amount":"SGD 1.00"}`),
			},
		}),
	})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	localErr, ok := result.(server.AuthorizationLocalError)
	if !ok {
		t.Fatalf("result = %T, want server.AuthorizationLocalError", result)
	}
	if localErr.Error.Code() != server.ErrorInvalidRequest {
		t.Fatalf("Error.Code() = %v, want %v", localErr.Error.Code(), server.ErrorInvalidRequest)
	}
}

func TestCompleteAuthorizationRejectsGrantedUnregisteredType(t *testing.T) {
	h := newHarnessWithRAR(t, server.ProfileFAPISecurity, newTestRARRegistry(t))

	pushResult, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: plainFormParameters(t, h.clientAssertion(t), map[string]string{
			"authorization_details": `[{"type":"payment","actions":["approve"]}]`,
		})},
	})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
	action, err := h.server.BeginAuthorization(context.Background(), server.BeginAuthorizationRequest{
		RequestURI: pushResult.RequestURI.String(), ClientID: testClientID,
	})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	interaction := action.(server.InteractionRequired)

	// Granting an object of a type this RARRegistry never registered at
	// all (not merely one absent from this particular request) must be
	// rejected the same way an unrequested object of a known type is.
	subject, authCtx := rarSubjectAndAuthCtx(t, h.now)
	result, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
		Handle: interaction.Handle,
		Result: server.Authorize(subject, authCtx, server.GrantedAuthorization{
			Scope: []string{"openid", "accounts"},
			AuthorizationDetails: []json.RawMessage{
				json.RawMessage(`{"type":"account_information","permissions":["ReadAccountsDetail"]}`),
			},
		}),
	})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	localErr, ok := result.(server.AuthorizationLocalError)
	if !ok {
		t.Fatalf("result = %T, want server.AuthorizationLocalError", result)
	}
	if localErr.Error.Code() != server.ErrorInvalidRequest {
		t.Fatalf("Error.Code() = %v, want %v", localErr.Error.Code(), server.ErrorInvalidRequest)
	}
}

// TestExchangeAuthorizationCodeMergesAuthorizationDetailsWithExistingTokenClaims
// covers withAuthorizationDetails merging into an already-non-empty
// claims map — the request here also asks for a userinfo claim via the
// standard "claims" parameter (OIDC Core §5.5), so
// withRequestedUserinfoClaims has already populated the access token's
// claims map by the time withAuthorizationDetails runs.
func TestExchangeAuthorizationCodeMergesAuthorizationDetailsWithExistingTokenClaims(t *testing.T) {
	h := newHarnessWithRAR(t, server.ProfileFAPISecurity, newTestRARRegistry(t))

	pushResult, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: plainFormParameters(t, h.clientAssertion(t), map[string]string{
			"authorization_details": `[{"type":"payment","actions":["approve"],"amount":"SGD 10.00"}]`,
			"claims":                `{"userinfo":{"email":null}}`,
		})},
	})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
	action, err := h.server.BeginAuthorization(context.Background(), server.BeginAuthorizationRequest{
		RequestURI: pushResult.RequestURI.String(), ClientID: testClientID,
	})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	interaction := action.(server.InteractionRequired)
	details, err := extension.RARGet(interaction.Interaction.AuthorizationDetails, paymentRARDef)
	if err != nil {
		t.Fatalf("RARGet: %v", err)
	}

	subject, authCtx := rarSubjectAndAuthCtx(t, h.now)
	result, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
		Handle: interaction.Handle,
		Result: server.Authorize(subject, authCtx, server.GrantedAuthorization{
			Scope:                []string{"openid", "accounts"},
			AuthorizationDetails: []json.RawMessage{mustMarshal(t, details[0].Fields)},
		}),
	})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	redirect := result.(server.AuthorizationRedirect)
	dest := redirect.Destination().URL()
	code := dest.Query().Get("code")

	dpopKey := generateKey(t)
	exchangeResult, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:      server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
		DPoPProof: createDPoPProof(t, dpopKey, h.now),
	})
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	if len(exchangeResult.AuthorizationDetails) == 0 {
		t.Fatalf("TokenResult.AuthorizationDetails is empty")
	}
	claim := authorizationDetailsAccessTokenClaim(t, exchangeResult.AccessToken.Reveal(), &h.serverKey.PublicKey)
	if len(claim) == 0 {
		t.Fatalf("access token authorization_details claim is empty")
	}
}

// --- PAR (signed request object path) ------------------------------------

func TestPushAuthorizationRequestJARAuthorizationDetailsAccepted(t *testing.T) {
	h := newHarnessWithRAR(t, server.ProfileFAPISecurity, newTestRARRegistry(t))

	params := standardAuthParams(t)
	params["authorization_details"] = jsonRaw(t, []testPaymentDetail{{Type: "payment", Actions: []string{"approve"}, Amount: "SGD 10.00"}})
	requestObj := h.requestObject(t, params)

	pushResult, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_assertion", h.clientAssertion(t)),
			formParam("client_assertion_type", clientassertion.AssertionType),
			formParam("request", requestObj),
		}},
	})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
	action, err := h.server.BeginAuthorization(context.Background(), server.BeginAuthorizationRequest{
		RequestURI: pushResult.RequestURI.String(), ClientID: testClientID,
	})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	interaction, ok := action.(server.InteractionRequired)
	if !ok {
		t.Fatalf("action = %T, want server.InteractionRequired", action)
	}
	details, err := extension.RARGet(interaction.Interaction.AuthorizationDetails, paymentRARDef)
	if err != nil {
		t.Fatalf("RARGet: %v", err)
	}
	if len(details) != 1 || details[0].Fields.Amount != "SGD 10.00" {
		t.Fatalf("RARGet returned %+v, want one SGD 10.00 payment", details)
	}
}

// --- CIBA ------------------------------------------------------------------

func TestCIBAAuthorizationDetailsFlow(t *testing.T) {
	h := newHarnessWithRAR(t, server.ProfileFAPISecurity, newTestRARRegistry(t))

	params := standardBackchannelParams(t)
	params["authorization_details"] = jsonRaw(t, []testPaymentDetail{
		{Type: "payment", Actions: []string{"approve"}, Amount: "SGD 500.00"},
	})
	required := beginBackchannel(t, h, params)

	details, err := extension.RARGet(required.Interaction.AuthorizationDetails, paymentRARDef)
	if err != nil {
		t.Fatalf("RARGet: %v", err)
	}
	if len(details) != 1 || details[0].Fields.Amount != "SGD 500.00" {
		t.Fatalf("RARGet returned %+v, want one SGD 500.00 payment", details)
	}

	subject, authCtx := rarSubjectAndAuthCtx(t, h.now)
	if err := h.server.CompleteBackchannelAuthentication(context.Background(), server.CompleteBackchannelAuthenticationRequest{
		Handle: required.Handle,
		Result: server.Authorize(subject, authCtx, server.GrantedAuthorization{
			Scope:                []string{"openid", "accounts"},
			AuthorizationDetails: []json.RawMessage{mustMarshal(t, details[0].Fields)},
		}),
	}); err != nil {
		t.Fatalf("CompleteBackchannelAuthentication: %v", err)
	}

	result, err := h.server.ExchangeBackchannelAuthentication(context.Background(), server.BackchannelTokenExchangeRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_assertion", h.clientAssertion(t)),
			formParam("client_assertion_type", clientassertion.AssertionType),
			formParam("grant_type", server.CIBAGrantType),
			formParam("auth_req_id", required.AuthReqID.String()),
		}},
		DPoPProof: createDPoPProof(t, generateKey(t), h.now),
	})
	if err != nil {
		t.Fatalf("ExchangeBackchannelAuthentication: %v", err)
	}

	var responseEchoed []testPaymentDetail
	if err := json.Unmarshal(result.AuthorizationDetails, &responseEchoed); err != nil {
		t.Fatalf("unmarshal TokenResult.AuthorizationDetails: %v", err)
	}
	if len(responseEchoed) != 1 || responseEchoed[0].Amount != "SGD 500.00" {
		t.Fatalf("TokenResult.AuthorizationDetails = %s, want the SGD 500.00 payment", result.AuthorizationDetails)
	}

	claim := authorizationDetailsAccessTokenClaim(t, result.AccessToken.Reveal(), &h.serverKey.PublicKey)
	var claimed []testPaymentDetail
	if err := json.Unmarshal(claim, &claimed); err != nil {
		t.Fatalf("unmarshal access token authorization_details claim: %v", err)
	}
	if len(claimed) != 1 || claimed[0].Amount != "SGD 500.00" {
		t.Fatalf("access token authorization_details claim = %s, want the SGD 500.00 payment", claim)
	}
}

func TestCompleteBackchannelAuthenticationRejectsUnrequestedAuthorizationDetails(t *testing.T) {
	h := newHarnessWithRAR(t, server.ProfileFAPISecurity, newTestRARRegistry(t))

	params := standardBackchannelParams(t)
	params["authorization_details"] = jsonRaw(t, []testPaymentDetail{
		{Type: "payment", Actions: []string{"approve"}, Amount: "SGD 10.00"},
	})
	required := beginBackchannel(t, h, params)

	subject, authCtx := rarSubjectAndAuthCtx(t, h.now)
	err := h.server.CompleteBackchannelAuthentication(context.Background(), server.CompleteBackchannelAuthenticationRequest{
		Handle: required.Handle,
		Result: server.Authorize(subject, authCtx, server.GrantedAuthorization{
			Scope: []string{"openid", "accounts"},
			AuthorizationDetails: []json.RawMessage{
				json.RawMessage(`{"type":"payment","actions":["approve"],"amount":"SGD 999999.00"}`),
			},
		}),
	})
	if err == nil {
		t.Fatalf("CompleteBackchannelAuthentication = nil error, want error")
	}
	if serverErrorCode(t, err) != server.ErrorInvalidRequest {
		t.Fatalf("error code = %v, want %v", serverErrorCode(t, err), server.ErrorInvalidRequest)
	}
}

func mustMarshal(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

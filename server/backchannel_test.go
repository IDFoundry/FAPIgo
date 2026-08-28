package server_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/internal/requestobject"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

const testBackchannelAuthenticationEndpoint = "https://as.example/backchannel-authenticate"
const testNotPermittedClientID = fapi.ClientID("not-ciba-permitted-client")

// newHarnessWithBackchannel mirrors newHarnessWithNonces' shape: a
// valid harness with CIBA fully configured (endpoint, algorithm
// allow-list, limits, a real memstore.BackchannelAuthenticationStore)
// and the registered client opted in via
// BackchannelAuthenticationRequestAlgorithm.
func newHarnessWithBackchannel(t *testing.T) (harness, *memstore.BackchannelAuthenticationStore) {
	t.Helper()
	now := time.Now()
	key := generateKey(t)
	serverKey := generateKey(t)

	client, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID:                       testClientID,
		RedirectURIs:             []fapi.RegisteredRedirectURI{testRedirectURI},
		ClientAssertionAlgorithm: fapi.ES256,
		AllowedScopes:            []string{"openid", "accounts", "offline_access"},
		BackchannelAuthenticationRequestAlgorithm: fapi.ES256,
	})
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}
	// Registered but not opted into CIBA (BackchannelAuthenticationRequestAlgorithm
	// left zero) — for TestBeginBackchannelAuthenticationRejectsClientNotPermitted.
	notPermittedClient, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID:                       testNotPermittedClientID,
		RedirectURIs:             []fapi.RegisteredRedirectURI{testRedirectURI},
		ClientAssertionAlgorithm: fapi.ES256,
		AllowedScopes:            []string{"openid", "accounts"},
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
		Profile:   server.ProfileFAPISecurity,
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
	}
	serverKeyManager := &fakeKeyManager{key: serverKey, keyID: "as-key-1"}
	backchannel := memstore.NewBackchannelAuthenticationStore()
	deps := server.Dependencies{
		Clients: &fakeClientRepository{clients: map[fapi.ClientID]storage.RegisteredClient{
			testClientID:             client,
			testNotPermittedClientID: notPermittedClient,
		}},
		Transactions: &fakeTransactionStore{},
		Grants:       &fakeGrantStore{},
		Replay:       &fakeReplayStore{},
		ClientKeys: &fakeClientKeySource{keysByClient: map[fapi.ClientID][]keys.VerificationKey{
			testClientID:             {{Algorithm: fapi.ES256, PublicKey: &key.PublicKey}},
			testNotPermittedClientID: {{Algorithm: fapi.ES256, PublicKey: &key.PublicKey}},
		}},
		Keys:         serverKeyManager,
		AccessTokens: server.JWTAccessTokens{Keys: serverKeyManager, Algorithm: fapi.ES256},
		Revocation:   server.NoRevocation{},
		Clock:        fixedClock{now: now},
		Random:       rand.Reader,
		Backchannel:  backchannel,
	}
	srv, err := server.New(cfg, deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return harness{server: srv, key: key, serverKey: serverKey, now: now}, backchannel
}

// backchannelRequestObject builds a signed CIBA backchannel
// authentication request object, mirroring harness.requestObject.
func (h harness) backchannelRequestObject(t *testing.T, params map[string]json.RawMessage) string {
	t.Helper()
	obj, err := requestobject.Create(requestobject.CreateParams{
		Signer: h.key, Algorithm: fapi.ES256,
		ClientID: testClientID.String(), Audience: testIssuer,
		Now: h.now, Lifetime: 30 * time.Second, Parameters: params,
	})
	if err != nil {
		t.Fatalf("requestobject.Create: %v", err)
	}
	return obj
}

func backchannelFormParams(assertion, requestObj string) []server.FormParameter {
	return []server.FormParameter{
		formParam("client_assertion", assertion),
		formParam("client_assertion_type", clientassertion.AssertionType),
		formParam("request", requestObj),
	}
}

func standardBackchannelParams(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	return map[string]json.RawMessage{
		"scope":      jsonRaw(t, "openid accounts"),
		"login_hint": jsonRaw(t, "user-1"),
	}
}

// --- Config/Dependencies validation ---------------------------------

// TestNewRejectsInvalidBackchannelAuthenticationConfig mirrors
// TestNewRejectsInvalidIDTokenEncryptionConfig's shape: every
// CIBA-specific requirement is conditional on
// Endpoints.BackchannelAuthentication being set, the same pattern
// JARMResponseLifetime already uses for
// ProfileFAPISecurityWithMessageSigning.
func TestNewRejectsInvalidBackchannelAuthenticationConfig(t *testing.T) {
	backchannelEndpoint, err := fapi.ParseEndpointURL(testBackchannelAuthenticationEndpoint)
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}

	cases := map[string]func(*server.Config){
		"empty algorithm allow-list": func(c *server.Config) {
			c.Endpoints.BackchannelAuthentication = backchannelEndpoint
		},
		"invalid algorithm in allow-list": func(c *server.Config) {
			c.Endpoints.BackchannelAuthentication = backchannelEndpoint
			c.Algorithms.BackchannelAuthenticationRequest = server.AlgorithmSet{fapi.SignatureAlgorithm(99)}
		},
		"zero request lifetime": func(c *server.Config) {
			c.Endpoints.BackchannelAuthentication = backchannelEndpoint
			c.Algorithms.BackchannelAuthenticationRequest = server.AlgorithmSet{fapi.ES256}
			c.Limits.MaxBackchannelAuthenticationRequestLifetime = time.Minute
			c.Limits.BackchannelAuthenticationPollInterval = time.Second
			c.Limits.BackchannelAuthenticationRequestLifetime = 0
		},
		"zero max request lifetime": func(c *server.Config) {
			c.Endpoints.BackchannelAuthentication = backchannelEndpoint
			c.Algorithms.BackchannelAuthenticationRequest = server.AlgorithmSet{fapi.ES256}
			c.Limits.BackchannelAuthenticationRequestLifetime = 2 * time.Minute
			c.Limits.BackchannelAuthenticationPollInterval = time.Second
			c.Limits.MaxBackchannelAuthenticationRequestLifetime = 0
		},
		"zero poll interval": func(c *server.Config) {
			c.Endpoints.BackchannelAuthentication = backchannelEndpoint
			c.Algorithms.BackchannelAuthenticationRequest = server.AlgorithmSet{fapi.ES256}
			c.Limits.BackchannelAuthenticationRequestLifetime = 2 * time.Minute
			c.Limits.MaxBackchannelAuthenticationRequestLifetime = time.Minute
			c.Limits.BackchannelAuthenticationPollInterval = 0
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := validConfig(t)
			mutate(&cfg)
			deps := validDependencies()
			deps.Backchannel = memstore.NewBackchannelAuthenticationStore()
			if _, err := server.New(cfg, deps); err == nil {
				t.Fatalf("New(%s) = nil error, want error", name)
			}
		})
	}
}

// TestNewRequiresBackchannelDependencyWhenConfigured mirrors
// TestNewRequiresClientEncryptionKeysWhenIDTokenEncryptionConfigured.
func TestNewRequiresBackchannelDependencyWhenConfigured(t *testing.T) {
	backchannelEndpoint, err := fapi.ParseEndpointURL(testBackchannelAuthenticationEndpoint)
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	cfg := validConfig(t)
	cfg.Endpoints.BackchannelAuthentication = backchannelEndpoint
	cfg.Algorithms.BackchannelAuthenticationRequest = server.AlgorithmSet{fapi.ES256}
	cfg.Limits.BackchannelAuthenticationRequestLifetime = 2 * time.Minute
	cfg.Limits.MaxBackchannelAuthenticationRequestLifetime = time.Minute
	cfg.Limits.BackchannelAuthenticationPollInterval = time.Second
	deps := validDependencies()

	if _, err := server.New(cfg, deps); err == nil {
		t.Fatalf("New(backchannel authentication configured, no Backchannel dependency) = nil error, want error")
	}

	deps.Backchannel = memstore.NewBackchannelAuthenticationStore()
	if _, err := server.New(cfg, deps); err != nil {
		t.Fatalf("New(backchannel authentication configured, with Backchannel dependency): %v", err)
	}
}

func TestBeginBackchannelAuthenticationSuccess(t *testing.T) {
	h, _ := newHarnessWithBackchannel(t)
	requestObj := h.backchannelRequestObject(t, standardBackchannelParams(t))

	action, err := h.server.BeginBackchannelAuthentication(context.Background(), server.BeginBackchannelAuthenticationRequest{
		HTTP: server.FormRequest{Parameters: backchannelFormParams(h.clientAssertion(t), requestObj)},
	})
	if err != nil {
		t.Fatalf("BeginBackchannelAuthentication: %v", err)
	}
	required, ok := action.(server.BackchannelInteractionRequired)
	if !ok {
		t.Fatalf("action = %T, want server.BackchannelInteractionRequired", action)
	}
	if required.AuthReqID.String() == "" {
		t.Fatalf("AuthReqID is empty")
	}
	if required.Handle.String() == "" {
		t.Fatalf("Handle is empty")
	}
	if required.ExpiresIn != 2*time.Minute {
		t.Fatalf("ExpiresIn = %v, want 2m", required.ExpiresIn)
	}
	if required.Interaction.ClientID != testClientID {
		t.Fatalf("Interaction.ClientID = %q, want %q", required.Interaction.ClientID, testClientID)
	}
	if required.Interaction.Hints.LoginHint != "user-1" {
		t.Fatalf("Interaction.Hints.LoginHint = %q, want %q", required.Interaction.Hints.LoginHint, "user-1")
	}
}

func TestBeginBackchannelAuthenticationRejectsMissingRequest(t *testing.T) {
	h, _ := newHarnessWithBackchannel(t)

	action, err := h.server.BeginBackchannelAuthentication(context.Background(), server.BeginBackchannelAuthenticationRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_assertion", h.clientAssertion(t)),
			formParam("client_assertion_type", clientassertion.AssertionType),
		}},
	})
	if err != nil {
		t.Fatalf("BeginBackchannelAuthentication: %v", err)
	}
	localErr, ok := action.(server.BackchannelAuthenticationLocalError)
	if !ok {
		t.Fatalf("action = %T, want server.BackchannelAuthenticationLocalError", action)
	}
	if localErr.Error.Code() != server.ErrorInvalidRequest {
		t.Fatalf("Code = %q, want %q", localErr.Error.Code(), server.ErrorInvalidRequest)
	}
}

func TestBeginBackchannelAuthenticationRejectsClientNotPermitted(t *testing.T) {
	h, _ := newHarnessWithBackchannel(t)

	assertion, err := clientassertion.CreateAssertion(clientassertion.AssertionRequest{
		Signer: h.key, Algorithm: fapi.ES256,
		ClientID: testNotPermittedClientID.String(), Audience: testIssuer,
		Now: h.now, Lifetime: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("CreateAssertion: %v", err)
	}
	requestObj, err := requestobject.Create(requestobject.CreateParams{
		Signer: h.key, Algorithm: fapi.ES256,
		ClientID: testNotPermittedClientID.String(), Audience: testIssuer,
		Now: h.now, Lifetime: 30 * time.Second, Parameters: standardBackchannelParams(t),
	})
	if err != nil {
		t.Fatalf("requestobject.Create: %v", err)
	}

	action, err := h.server.BeginBackchannelAuthentication(context.Background(), server.BeginBackchannelAuthenticationRequest{
		HTTP: server.FormRequest{Parameters: backchannelFormParams(assertion, requestObj)},
	})
	if err != nil {
		t.Fatalf("BeginBackchannelAuthentication: %v", err)
	}
	localErr, ok := action.(server.BackchannelAuthenticationLocalError)
	if !ok {
		t.Fatalf("action = %T, want server.BackchannelAuthenticationLocalError", action)
	}
	if localErr.Error.Code() != server.ErrorInvalidRequest {
		t.Fatalf("Code = %q, want %q", localErr.Error.Code(), server.ErrorInvalidRequest)
	}
}

func TestBeginBackchannelAuthenticationRejectsMultipleHints(t *testing.T) {
	h, _ := newHarnessWithBackchannel(t)
	params := standardBackchannelParams(t)
	params["id_token_hint"] = jsonRaw(t, "some-id-token")
	requestObj := h.backchannelRequestObject(t, params)

	action, err := h.server.BeginBackchannelAuthentication(context.Background(), server.BeginBackchannelAuthenticationRequest{
		HTTP: server.FormRequest{Parameters: backchannelFormParams(h.clientAssertion(t), requestObj)},
	})
	if err != nil {
		t.Fatalf("BeginBackchannelAuthentication: %v", err)
	}
	localErr, ok := action.(server.BackchannelAuthenticationLocalError)
	if !ok {
		t.Fatalf("action = %T, want server.BackchannelAuthenticationLocalError", action)
	}
	if localErr.Error.Code() != server.ErrorInvalidRequest {
		t.Fatalf("Code = %q, want %q", localErr.Error.Code(), server.ErrorInvalidRequest)
	}
}

func TestBeginBackchannelAuthenticationRejectsNoHints(t *testing.T) {
	h, _ := newHarnessWithBackchannel(t)
	requestObj := h.backchannelRequestObject(t, map[string]json.RawMessage{
		"scope": jsonRaw(t, "openid accounts"),
	})

	action, err := h.server.BeginBackchannelAuthentication(context.Background(), server.BeginBackchannelAuthenticationRequest{
		HTTP: server.FormRequest{Parameters: backchannelFormParams(h.clientAssertion(t), requestObj)},
	})
	if err != nil {
		t.Fatalf("BeginBackchannelAuthentication: %v", err)
	}
	localErr, ok := action.(server.BackchannelAuthenticationLocalError)
	if !ok {
		t.Fatalf("action = %T, want server.BackchannelAuthenticationLocalError", action)
	}
	if localErr.Error.Code() != server.ErrorInvalidRequest {
		t.Fatalf("Code = %q, want %q", localErr.Error.Code(), server.ErrorInvalidRequest)
	}
}

func TestBeginBackchannelAuthenticationRejectsPingMode(t *testing.T) {
	h, _ := newHarnessWithBackchannel(t)
	params := standardBackchannelParams(t)
	params["client_notification_token"] = jsonRaw(t, "notify-me")
	requestObj := h.backchannelRequestObject(t, params)

	action, err := h.server.BeginBackchannelAuthentication(context.Background(), server.BeginBackchannelAuthenticationRequest{
		HTTP: server.FormRequest{Parameters: backchannelFormParams(h.clientAssertion(t), requestObj)},
	})
	if err != nil {
		t.Fatalf("BeginBackchannelAuthentication: %v", err)
	}
	localErr, ok := action.(server.BackchannelAuthenticationLocalError)
	if !ok {
		t.Fatalf("action = %T, want server.BackchannelAuthenticationLocalError", action)
	}
	if localErr.Error.Code() != server.ErrorInvalidRequest {
		t.Fatalf("Code = %q, want %q", localErr.Error.Code(), server.ErrorInvalidRequest)
	}
}

func TestBeginBackchannelAuthenticationRejectsWhenCIBADisabled(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true) // CIBA not configured

	action, err := h.server.BeginBackchannelAuthentication(context.Background(), server.BeginBackchannelAuthenticationRequest{
		HTTP: server.FormRequest{Parameters: backchannelFormParams(h.clientAssertion(t), "irrelevant")},
	})
	if err != nil {
		t.Fatalf("BeginBackchannelAuthentication: %v", err)
	}
	localErr, ok := action.(server.BackchannelAuthenticationLocalError)
	if !ok {
		t.Fatalf("action = %T, want server.BackchannelAuthenticationLocalError", action)
	}
	if localErr.Error.Code() != server.ErrorServerError {
		t.Fatalf("Code = %q, want %q", localErr.Error.Code(), server.ErrorServerError)
	}
}

// beginBackchannel is a small helper that drives BeginBackchannelAuthentication
// to a successful BackchannelInteractionRequired, for tests that need to
// go on to CompleteBackchannelAuthentication/ExchangeBackchannelAuthentication.
func beginBackchannel(t *testing.T, h harness, params map[string]json.RawMessage) server.BackchannelInteractionRequired {
	t.Helper()
	requestObj := h.backchannelRequestObject(t, params)
	action, err := h.server.BeginBackchannelAuthentication(context.Background(), server.BeginBackchannelAuthenticationRequest{
		HTTP: server.FormRequest{Parameters: backchannelFormParams(h.clientAssertion(t), requestObj)},
	})
	if err != nil {
		t.Fatalf("BeginBackchannelAuthentication: %v", err)
	}
	required, ok := action.(server.BackchannelInteractionRequired)
	if !ok {
		t.Fatalf("action = %T, want server.BackchannelInteractionRequired", action)
	}
	return required
}

func TestCIBAFullFlowApproved(t *testing.T) {
	h, _ := newHarnessWithBackchannel(t)
	required := beginBackchannel(t, h, standardBackchannelParams(t))

	subject, err := server.NewSubjectID("user-1")
	if err != nil {
		t.Fatalf("NewSubjectID: %v", err)
	}
	authenticated, err := server.NewAuthenticatedSubject(subject)
	if err != nil {
		t.Fatalf("NewAuthenticatedSubject: %v", err)
	}
	authCtx, err := server.NewAuthenticationContext(h.now, "acr-1", []string{"pwd"})
	if err != nil {
		t.Fatalf("NewAuthenticationContext: %v", err)
	}

	if err := h.server.CompleteBackchannelAuthentication(context.Background(), server.CompleteBackchannelAuthenticationRequest{
		Handle: required.Handle,
		Result: server.Authorize(authenticated, authCtx, server.GrantedAuthorization{Scope: []string{"openid", "accounts"}}),
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
	if result.AccessToken.Reveal() == "" {
		t.Fatalf("AccessToken is empty")
	}
	if !result.HasIDToken || result.IDToken.Reveal() == "" {
		t.Fatalf("expected an ID token since scope included openid")
	}

	// A second poll for the same auth_req_id must fail — tokens are
	// issued exactly once.
	_, err = h.server.ExchangeBackchannelAuthentication(context.Background(), server.BackchannelTokenExchangeRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_assertion", h.clientAssertion(t)),
			formParam("client_assertion_type", clientassertion.AssertionType),
			formParam("grant_type", server.CIBAGrantType),
			formParam("auth_req_id", required.AuthReqID.String()),
		}},
		DPoPProof: createDPoPProof(t, generateKey(t), h.now),
	})
	if err == nil {
		t.Fatalf("second ExchangeBackchannelAuthentication = nil error, want error")
	}
}

func TestCIBAFullFlowDenied(t *testing.T) {
	h, _ := newHarnessWithBackchannel(t)
	required := beginBackchannel(t, h, standardBackchannelParams(t))

	if err := h.server.CompleteBackchannelAuthentication(context.Background(), server.CompleteBackchannelAuthenticationRequest{
		Handle: required.Handle,
		Result: server.Deny("user declined"),
	}); err != nil {
		t.Fatalf("CompleteBackchannelAuthentication: %v", err)
	}

	_, err := h.server.ExchangeBackchannelAuthentication(context.Background(), server.BackchannelTokenExchangeRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_assertion", h.clientAssertion(t)),
			formParam("client_assertion_type", clientassertion.AssertionType),
			formParam("grant_type", server.CIBAGrantType),
			formParam("auth_req_id", required.AuthReqID.String()),
		}},
		DPoPProof: createDPoPProof(t, generateKey(t), h.now),
	})
	if err == nil {
		t.Fatalf("ExchangeBackchannelAuthentication(denied) = nil error, want error")
	}
	if code := serverErrorCode(t, err); code != server.ErrorAccessDenied {
		t.Fatalf("error code = %q, want %q", code, server.ErrorAccessDenied)
	}
}

func TestCompleteBackchannelAuthenticationIsSingleUse(t *testing.T) {
	h, _ := newHarnessWithBackchannel(t)
	required := beginBackchannel(t, h, standardBackchannelParams(t))

	if err := h.server.CompleteBackchannelAuthentication(context.Background(), server.CompleteBackchannelAuthenticationRequest{
		Handle: required.Handle,
		Result: server.Deny(""),
	}); err != nil {
		t.Fatalf("first CompleteBackchannelAuthentication: %v", err)
	}
	if err := h.server.CompleteBackchannelAuthentication(context.Background(), server.CompleteBackchannelAuthenticationRequest{
		Handle: required.Handle,
		Result: server.Deny(""),
	}); err == nil {
		t.Fatalf("second CompleteBackchannelAuthentication = nil error, want error")
	}
}

func TestExchangeBackchannelAuthenticationBeforeDecisionIsPending(t *testing.T) {
	h, _ := newHarnessWithBackchannel(t)
	required := beginBackchannel(t, h, standardBackchannelParams(t))

	_, err := h.server.ExchangeBackchannelAuthentication(context.Background(), server.BackchannelTokenExchangeRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_assertion", h.clientAssertion(t)),
			formParam("client_assertion_type", clientassertion.AssertionType),
			formParam("grant_type", server.CIBAGrantType),
			formParam("auth_req_id", required.AuthReqID.String()),
		}},
		DPoPProof: createDPoPProof(t, generateKey(t), h.now),
	})
	if err == nil {
		t.Fatalf("ExchangeBackchannelAuthentication(pending) = nil error, want error")
	}
	if code := serverErrorCode(t, err); code != server.ErrorAuthorizationPending {
		t.Fatalf("error code = %q, want %q", code, server.ErrorAuthorizationPending)
	}
}

func TestExchangeBackchannelAuthenticationRejectsUnknownAuthReqID(t *testing.T) {
	h, _ := newHarnessWithBackchannel(t)

	_, err := h.server.ExchangeBackchannelAuthentication(context.Background(), server.BackchannelTokenExchangeRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_assertion", h.clientAssertion(t)),
			formParam("client_assertion_type", clientassertion.AssertionType),
			formParam("grant_type", server.CIBAGrantType),
			formParam("auth_req_id", "never-issued"),
		}},
		DPoPProof: createDPoPProof(t, generateKey(t), h.now),
	})
	if err == nil {
		t.Fatalf("ExchangeBackchannelAuthentication(unknown auth_req_id) = nil error, want error")
	}
	if code := serverErrorCode(t, err); code != server.ErrorInvalidGrant {
		t.Fatalf("error code = %q, want %q", code, server.ErrorInvalidGrant)
	}
}

func TestExchangeBackchannelAuthenticationRejectsWrongGrantType(t *testing.T) {
	h, _ := newHarnessWithBackchannel(t)

	_, err := h.server.ExchangeBackchannelAuthentication(context.Background(), server.BackchannelTokenExchangeRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_assertion", h.clientAssertion(t)),
			formParam("client_assertion_type", clientassertion.AssertionType),
			formParam("grant_type", "authorization_code"),
			formParam("auth_req_id", "whatever"),
		}},
		DPoPProof: createDPoPProof(t, generateKey(t), h.now),
	})
	if err == nil {
		t.Fatalf("ExchangeBackchannelAuthentication(wrong grant_type) = nil error, want error")
	}
	if code := serverErrorCode(t, err); code != server.ErrorUnsupportedGrantType {
		t.Fatalf("error code = %q, want %q", code, server.ErrorUnsupportedGrantType)
	}
}

func TestMetadataOmitsBackchannelAuthenticationWhenNotConfigured(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	md := h.server.Metadata(context.Background())

	if !md.BackchannelAuthenticationEndpoint.IsZero() {
		t.Fatalf("BackchannelAuthenticationEndpoint = %v, want zero", md.BackchannelAuthenticationEndpoint)
	}
	if len(md.BackchannelTokenDeliveryModesSupported) != 0 {
		t.Fatalf("BackchannelTokenDeliveryModesSupported = %v, want empty", md.BackchannelTokenDeliveryModesSupported)
	}
	for _, grantType := range md.GrantTypesSupported {
		if grantType == server.CIBAGrantType {
			t.Fatalf("GrantTypesSupported = %v, want no CIBA grant type", md.GrantTypesSupported)
		}
	}
}

func TestMetadataAdvertisesBackchannelAuthenticationWhenConfigured(t *testing.T) {
	h, _ := newHarnessWithBackchannel(t)
	md := h.server.Metadata(context.Background())

	if md.BackchannelAuthenticationEndpoint.String() != testBackchannelAuthenticationEndpoint {
		t.Fatalf("BackchannelAuthenticationEndpoint = %q, want %q", md.BackchannelAuthenticationEndpoint.String(), testBackchannelAuthenticationEndpoint)
	}
	if !containsString(md.BackchannelTokenDeliveryModesSupported, "poll") {
		t.Fatalf("BackchannelTokenDeliveryModesSupported = %v, want to contain poll", md.BackchannelTokenDeliveryModesSupported)
	}
	if !containsString(md.BackchannelAuthenticationRequestSigningAlgValuesSupported, "ES256") {
		t.Fatalf("BackchannelAuthenticationRequestSigningAlgValuesSupported = %v, want to contain ES256", md.BackchannelAuthenticationRequestSigningAlgValuesSupported)
	}
	found := false
	for _, grantType := range md.GrantTypesSupported {
		if grantType == server.CIBAGrantType {
			found = true
		}
	}
	if !found {
		t.Fatalf("GrantTypesSupported = %v, want to contain %q", md.GrantTypesSupported, server.CIBAGrantType)
	}
}

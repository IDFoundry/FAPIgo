package server_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/internal/mtls"
	"github.com/idfoundry/fapigo/internal/requestobject"
	"github.com/idfoundry/fapigo/internal/token"
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
		Keys:                serverKeyManager,
		AccessTokens:        server.JWTAccessTokens{Keys: serverKeyManager, Algorithm: fapi.ES256},
		Revocation:          server.NoRevocation{},
		Clock:               fixedClock{now: now},
		Random:              rand.Reader,
		Backchannel:         backchannel,
		BackchannelNotifier: server.NoBackchannelNotifications{},
	}
	srv, err := server.New(cfg, deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return harness{server: srv, key: key, serverKey: serverKey, now: now}, backchannel
}

// newHarnessWithBackchannelMTLS mirrors newHarnessWithBackchannel
// exactly, except testClientID is registered with SenderConstrain:
// storage.SenderConstrainMTLS instead of the default DPoP. Client
// *authentication* (client_assertion, via h.clientAssertion) is
// unaffected either way — SenderConstrain only governs how the
// eventual access token is bound, not how the client authenticates —
// so beginBackchannel is reused unchanged; only
// ExchangeBackchannelAuthentication needs a peer certificate instead
// of a DPoP proof, mirroring newHarnessWithSenderConstrainMTLS's own
// PAR/token-flow precedent (mtls_test.go).
func newHarnessWithBackchannelMTLS(t *testing.T) harness {
	t.Helper()
	now := time.Now()
	key := generateKey(t)
	serverKey := generateKey(t)

	client, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID:                       testClientID,
		RedirectURIs:             []fapi.RegisteredRedirectURI{testRedirectURI},
		ClientAssertionAlgorithm: fapi.ES256,
		SenderConstrain:          storage.SenderConstrainMTLS,
		AllowedScopes:            []string{"openid", "accounts", "offline_access"},
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

const testBackchannelClientNotificationEndpoint = "https://rp.example/ciba/notify"

// fakeBackchannelNotifier records every Notify call it receives — used
// to confirm CompleteBackchannelAuthentication dispatches exactly one
// ping notification, with the right endpoint/token, and to inject a
// failure to confirm it never fails the decision itself.
type fakeBackchannelNotifier struct {
	mu    sync.Mutex
	calls []server.BackchannelNotification
	err   error
}

func (f *fakeBackchannelNotifier) Notify(_ context.Context, notification server.BackchannelNotification) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, notification)
	return f.err
}

func (f *fakeBackchannelNotifier) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *fakeBackchannelNotifier) lastCall() server.BackchannelNotification {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[len(f.calls)-1]
}

// newHarnessWithBackchannelPing mirrors newHarnessWithBackchannel
// exactly, except testClientID is registered
// storage.BackchannelTokenDeliveryModePing (with a notification
// endpoint) instead of the default Poll, and Dependencies.BackchannelNotifier
// is a *fakeBackchannelNotifier a test can inspect directly, rather
// than the usual NoBackchannelNotifications{} no-op.
func newHarnessWithBackchannelPing(t *testing.T) (harness, *memstore.BackchannelAuthenticationStore, *fakeBackchannelNotifier) {
	t.Helper()
	now := time.Now()
	key := generateKey(t)
	serverKey := generateKey(t)

	notificationEndpoint, err := fapi.ParseEndpointURL(testBackchannelClientNotificationEndpoint)
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	client, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID:                       testClientID,
		RedirectURIs:             []fapi.RegisteredRedirectURI{testRedirectURI},
		ClientAssertionAlgorithm: fapi.ES256,
		AllowedScopes:            []string{"openid", "accounts", "offline_access"},
		BackchannelAuthenticationRequestAlgorithm: fapi.ES256,
		BackchannelTokenDeliveryMode:              storage.BackchannelTokenDeliveryModePing,
		BackchannelClientNotificationEndpoint:     notificationEndpoint,
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
	notifier := &fakeBackchannelNotifier{}
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
		Backchannel:         backchannel,
		BackchannelNotifier: notifier,
	}
	srv, err := server.New(cfg, deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return harness{server: srv, key: key, serverKey: serverKey, now: now}, backchannel, notifier
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
	if _, err := server.New(cfg, deps); err == nil {
		t.Fatalf("New(backchannel authentication configured, no BackchannelNotifier dependency) = nil error, want error")
	}

	deps.BackchannelNotifier = server.NoBackchannelNotifications{}
	if _, err := server.New(cfg, deps); err != nil {
		t.Fatalf("New(backchannel authentication configured, with Backchannel/BackchannelNotifier dependencies): %v", err)
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

func TestBeginBackchannelAuthenticationRejectsMalformedRequestObject(t *testing.T) {
	h, _ := newHarnessWithBackchannel(t)

	action, err := h.server.BeginBackchannelAuthentication(context.Background(), server.BeginBackchannelAuthenticationRequest{
		HTTP: server.FormRequest{Parameters: backchannelFormParams(h.clientAssertion(t), "not-a-valid-jwt")},
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

func TestBeginBackchannelAuthenticationRejectsNoMatchingClientKey(t *testing.T) {
	h, _ := newHarnessWithBackchannel(t)
	decoyKey := generateKey(t)
	requestObj, err := requestobject.Create(requestobject.CreateParams{
		Signer: decoyKey, Algorithm: fapi.ES256,
		ClientID: testClientID.String(), Audience: testIssuer,
		Now: h.now, Lifetime: 30 * time.Second, Parameters: standardBackchannelParams(t),
	})
	if err != nil {
		t.Fatalf("requestobject.Create: %v", err)
	}

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

func TestBeginBackchannelAuthenticationRejectsInvalidScope(t *testing.T) {
	cases := map[string]map[string]json.RawMessage{
		"missing scope": {
			"login_hint": jsonRaw(t, "user-1"),
		},
		"scope is not a string": {
			"scope": jsonRaw(t, 123), "login_hint": jsonRaw(t, "user-1"),
		},
		"scope not allowed for this client": {
			"scope": jsonRaw(t, "openid unregistered_scope"), "login_hint": jsonRaw(t, "user-1"),
		},
	}
	for name, params := range cases {
		t.Run(name, func(t *testing.T) {
			h, _ := newHarnessWithBackchannel(t)
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
		})
	}
}

func TestBeginBackchannelAuthenticationRejectsUnregisteredExtensionParameter(t *testing.T) {
	h, _ := newHarnessWithBackchannel(t)
	params := standardBackchannelParams(t)
	params["bogus_extension_parameter"] = jsonRaw(t, "value")
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

// TestBeginBackchannelAuthenticationRejectsNotificationTokenForPollClient
// covers a poll-mode client (newHarnessWithBackchannel's own default
// registration) sending client_notification_token anyway — CIBA §7.1
// only makes the parameter meaningful for ping/push.
func TestBeginBackchannelAuthenticationRejectsNotificationTokenForPollClient(t *testing.T) {
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

// TestBeginBackchannelAuthenticationRejectsMissingNotificationTokenForPingClient
// covers the opposite shape mismatch: a client registered for ping
// delivery (newHarnessWithBackchannelPing) omitting
// client_notification_token entirely.
func TestBeginBackchannelAuthenticationRejectsMissingNotificationTokenForPingClient(t *testing.T) {
	h, _, _ := newHarnessWithBackchannelPing(t)
	requestObj := h.backchannelRequestObject(t, standardBackchannelParams(t))

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

func TestBeginBackchannelAuthenticationAcceptsNotificationTokenForPingClient(t *testing.T) {
	h, _, _ := newHarnessWithBackchannelPing(t)
	params := standardBackchannelParams(t)
	params["client_notification_token"] = jsonRaw(t, "notify-me")
	requestObj := h.backchannelRequestObject(t, params)

	action, err := h.server.BeginBackchannelAuthentication(context.Background(), server.BeginBackchannelAuthenticationRequest{
		HTTP: server.FormRequest{Parameters: backchannelFormParams(h.clientAssertion(t), requestObj)},
	})
	if err != nil {
		t.Fatalf("BeginBackchannelAuthentication: %v", err)
	}
	if _, ok := action.(server.BackchannelInteractionRequired); !ok {
		t.Fatalf("action = %T, want server.BackchannelInteractionRequired", action)
	}
}

// TestCompleteBackchannelAuthenticationDispatchesPingNotification covers
// the actual dispatch: a ping-registered client's decision, regardless
// of outcome (Approved here; TestCompleteBackchannelAuthenticationDispatchesPingNotificationOnDenied
// covers Denied), fires exactly one Notify call carrying the client's
// own registered endpoint and the token it sent with its original
// request.
func TestCompleteBackchannelAuthenticationDispatchesPingNotification(t *testing.T) {
	h, _, notifier := newHarnessWithBackchannelPing(t)
	params := standardBackchannelParams(t)
	params["client_notification_token"] = jsonRaw(t, "notify-me-123")
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

	if notifier.callCount() != 1 {
		t.Fatalf("Notify call count = %d, want 1", notifier.callCount())
	}
	call := notifier.lastCall()
	if call.Endpoint.String() != testBackchannelClientNotificationEndpoint {
		t.Fatalf("Endpoint = %v, want %q", call.Endpoint, testBackchannelClientNotificationEndpoint)
	}
	if call.ClientNotificationToken.Reveal() != "notify-me-123" {
		t.Fatalf("ClientNotificationToken = %q, want %q", call.ClientNotificationToken.Reveal(), "notify-me-123")
	}
	if call.AuthReqID != required.AuthReqID.String() {
		t.Fatalf("AuthReqID = %q, want %q (CIBA §10.2 requires the notification body carry it)", call.AuthReqID, required.AuthReqID.String())
	}
}

// TestCompleteBackchannelAuthenticationDispatchesPingNotificationOnDenied
// confirms dispatch is unconditional on decision outcome — a client
// registered for ping delivery needs to know "go poll now" whether the
// end user approved or denied the request.
func TestCompleteBackchannelAuthenticationDispatchesPingNotificationOnDenied(t *testing.T) {
	h, _, notifier := newHarnessWithBackchannelPing(t)
	params := standardBackchannelParams(t)
	params["client_notification_token"] = jsonRaw(t, "notify-me-456")
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

	if err := h.server.CompleteBackchannelAuthentication(context.Background(), server.CompleteBackchannelAuthenticationRequest{
		Handle: required.Handle,
		Result: server.Deny("user declined"),
	}); err != nil {
		t.Fatalf("CompleteBackchannelAuthentication: %v", err)
	}

	if notifier.callCount() != 1 {
		t.Fatalf("Notify call count = %d, want 1", notifier.callCount())
	}
	if notifier.lastCall().ClientNotificationToken.Reveal() != "notify-me-456" {
		t.Fatalf("ClientNotificationToken = %q, want %q", notifier.lastCall().ClientNotificationToken.Reveal(), "notify-me-456")
	}
}

// TestCompleteBackchannelAuthenticationIgnoresNotifierError confirms a
// failed ping dispatch never fails the decision itself — CIBA §10.3's
// backup-polling guarantee means the client is never left stuck even
// when this call fails outright.
func TestCompleteBackchannelAuthenticationIgnoresNotifierError(t *testing.T) {
	h, _, notifier := newHarnessWithBackchannelPing(t)
	notifier.err = fmt.Errorf("simulated network failure")
	params := standardBackchannelParams(t)
	params["client_notification_token"] = jsonRaw(t, "notify-me-789")
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
		t.Fatalf("CompleteBackchannelAuthentication returned an error even though only the notifier failed: %v", err)
	}
	if notifier.callCount() != 1 {
		t.Fatalf("Notify call count = %d, want 1", notifier.callCount())
	}
}

func TestBeginBackchannelAuthenticationAcceptsOrdinaryBindingMessage(t *testing.T) {
	h, _ := newHarnessWithBackchannel(t)
	params := standardBackchannelParams(t)
	params["binding_message"] = jsonRaw(t, "1234")
	requestObj := h.backchannelRequestObject(t, params)

	action, err := h.server.BeginBackchannelAuthentication(context.Background(), server.BeginBackchannelAuthenticationRequest{
		HTTP: server.FormRequest{Parameters: backchannelFormParams(h.clientAssertion(t), requestObj)},
	})
	if err != nil {
		t.Fatalf("BeginBackchannelAuthentication: %v", err)
	}
	if _, ok := action.(server.BackchannelInteractionRequired); !ok {
		t.Fatalf("action = %T, want server.BackchannelInteractionRequired", action)
	}
}

// TestBeginBackchannelAuthenticationAcceptsNonLatinAndEmojiBindingMessage
// confirms the acceptability check is about length and
// control/line-separator characters only — ordinary punctuation, emoji,
// and non-Latin scripts are all legitimate human-readable content and
// must not be rejected just because they aren't ASCII.
func TestBeginBackchannelAuthenticationAcceptsNonLatinAndEmojiBindingMessage(t *testing.T) {
	h, _ := newHarnessWithBackchannel(t)
	params := standardBackchannelParams(t)
	params["binding_message"] = jsonRaw(t, "1234 \U0001F44D\U0001F3FF 品川")
	requestObj := h.backchannelRequestObject(t, params)

	action, err := h.server.BeginBackchannelAuthentication(context.Background(), server.BeginBackchannelAuthenticationRequest{
		HTTP: server.FormRequest{Parameters: backchannelFormParams(h.clientAssertion(t), requestObj)},
	})
	if err != nil {
		t.Fatalf("BeginBackchannelAuthentication: %v", err)
	}
	if _, ok := action.(server.BackchannelInteractionRequired); !ok {
		t.Fatalf("action = %T, want server.BackchannelInteractionRequired", action)
	}
}

// TestBeginBackchannelAuthenticationRejectsOverlongBindingMessage covers
// CIBA §13's invalid_binding_message: a binding_message far longer than
// any real display surface can show at a glance is rejected outright,
// rather than accepted and handed to an out-of-band consent UI that may
// not be able to render it faithfully.
func TestBeginBackchannelAuthenticationRejectsOverlongBindingMessage(t *testing.T) {
	h, _ := newHarnessWithBackchannel(t)
	params := standardBackchannelParams(t)
	params["binding_message"] = jsonRaw(t, strings.Repeat("a", 101))
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
	if localErr.Error.Code() != server.ErrorInvalidBindingMessage {
		t.Fatalf("Code = %q, want %q", localErr.Error.Code(), server.ErrorInvalidBindingMessage)
	}
}

func TestBeginBackchannelAuthenticationRejectsBindingMessageWithControlCharacter(t *testing.T) {
	h, _ := newHarnessWithBackchannel(t)
	params := standardBackchannelParams(t)
	params["binding_message"] = jsonRaw(t, "1234\n5678")
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
	if localErr.Error.Code() != server.ErrorInvalidBindingMessage {
		t.Fatalf("Code = %q, want %q", localErr.Error.Code(), server.ErrorInvalidBindingMessage)
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

// TestCIBAFullFlowApprovedWithMTLSBinding is TestCIBAFullFlowApproved's
// SenderConstrainMTLS counterpart — the AS-side gap this test was
// specifically added to close: nothing previously exercised a CIBA
// token issued under mTLS sender-constraining at all (confirmed absent
// by grepping every server/*_test.go for SenderConstrainMTLS alongside
// Backchannel before adding this). Client *authentication* still uses
// h.clientAssertion(t) unchanged — only the token-exchange step's
// binding mechanism differs (PeerCertificate instead of DPoPProof).
func TestCIBAFullFlowApprovedWithMTLSBinding(t *testing.T) {
	h := newHarnessWithBackchannelMTLS(t)
	required := beginBackchannel(t, h, standardBackchannelParams(t))
	cert := selfSignedTestClientCert(t)

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
		PeerCertificate: cert,
	})
	if err != nil {
		t.Fatalf("ExchangeBackchannelAuthentication: %v", err)
	}
	if result.TokenType != "Bearer" {
		t.Fatalf("TokenType = %q, want %q (RFC 8705 §3.4)", result.TokenType, "Bearer")
	}

	parsedAT, err := token.ParseAccessToken(result.AccessToken.Reveal())
	if err != nil {
		t.Fatalf("ParseAccessToken: %v", err)
	}
	validatedAT, err := parsedAT.Validate(&h.serverKey.PublicKey, token.AccessTokenValidatePolicy{
		ExpectedIssuer: testIssuer, ExpectedAudience: testIssuer,
		Algorithm: fapi.ES256, Now: h.now, MaxLifetime: 10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Validate access token: %v", err)
	}
	if validatedAT.X5TS256 != mtls.Thumbprint(cert) {
		t.Fatalf("access token X5TS256 = %q, want %q", validatedAT.X5TS256, mtls.Thumbprint(cert))
	}
	if validatedAT.JKT != "" {
		t.Fatalf("access token JKT = %q, want empty (mTLS-bound, not DPoP-bound)", validatedAT.JKT)
	}
}

// TestExchangeBackchannelAuthenticationMTLSRequiresPeerCertificate
// covers the negative counterpart: an mTLS-sender-constrained client
// polling the token endpoint with no client certificate presented must
// be rejected, mirroring TestExchangeAuthorizationCodeMTLSRequiresPeerCertificate
// (mtls_test.go) for the authorization-code flow.
func TestExchangeBackchannelAuthenticationMTLSRequiresPeerCertificate(t *testing.T) {
	h := newHarnessWithBackchannelMTLS(t)
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

	_, err = h.server.ExchangeBackchannelAuthentication(context.Background(), server.BackchannelTokenExchangeRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_assertion", h.clientAssertion(t)),
			formParam("client_assertion_type", clientassertion.AssertionType),
			formParam("grant_type", server.CIBAGrantType),
			formParam("auth_req_id", required.AuthReqID.String()),
		}},
		// PeerCertificate intentionally omitted.
	})
	if err == nil {
		t.Fatalf("ExchangeBackchannelAuthentication(no peer certificate) = nil error, want error")
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
	if !containsString(md.BackchannelTokenDeliveryModesSupported, "ping") {
		t.Fatalf("BackchannelTokenDeliveryModesSupported = %v, want to contain ping", md.BackchannelTokenDeliveryModesSupported)
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

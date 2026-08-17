package server_test

import (
	"context"
	"crypto/rand"
	"sync"
	"testing"
	"time"

	fapi "github.com/osanderson/go-fapi"
	"github.com/osanderson/go-fapi/internal/clientassertion"
	"github.com/osanderson/go-fapi/keys"
	"github.com/osanderson/go-fapi/server"
	"github.com/osanderson/go-fapi/storage"
)

func pushAndBegin(t *testing.T, h harness, extraParams map[string]string) server.AuthorizationAction {
	t.Helper()
	pushResult, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: plainFormParameters(t, h.clientAssertion(t), extraParams)},
	})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
	action, err := h.server.BeginAuthorization(context.Background(), server.BeginAuthorizationRequest{
		RequestURI: pushResult.RequestURI.String(),
		ClientID:   testClientID,
	})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	return action
}

func TestBeginAuthorizationSuccess(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	action := pushAndBegin(t, h, map[string]string{"login_hint": "alice@example.com"})

	required, ok := action.(server.InteractionRequired)
	if !ok {
		t.Fatalf("action = %T, want server.InteractionRequired", action)
	}
	if required.Handle.String() == "" {
		t.Fatalf("Handle is empty")
	}
	if required.Interaction.ClientID != testClientID {
		t.Fatalf("Interaction.ClientID = %q, want %q", required.Interaction.ClientID, testClientID)
	}
	wantScopes := []string{"openid", "accounts"}
	if len(required.Interaction.Scope) != len(wantScopes) {
		t.Fatalf("Interaction.Scope = %v, want %v", required.Interaction.Scope, wantScopes)
	}
	for i, s := range wantScopes {
		if required.Interaction.Scope[i] != s {
			t.Fatalf("Interaction.Scope = %v, want %v", required.Interaction.Scope, wantScopes)
		}
	}
	if required.Interaction.Hints.LoginHint != "alice@example.com" {
		t.Fatalf("Hints.LoginHint = %q, want %q", required.Interaction.Hints.LoginHint, "alice@example.com")
	}
}

func TestBeginAuthorizationTwoHandlesAreDistinct(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	a1 := pushAndBegin(t, h, nil)
	a2 := pushAndBegin(t, h, nil)

	r1, ok := a1.(server.InteractionRequired)
	if !ok {
		t.Fatalf("a1 = %T, want InteractionRequired", a1)
	}
	r2, ok := a2.(server.InteractionRequired)
	if !ok {
		t.Fatalf("a2 = %T, want InteractionRequired", a2)
	}
	if r1.Handle.String() == r2.Handle.String() {
		t.Fatalf("two BeginAuthorization calls produced the same handle")
	}
}

func TestBeginAuthorizationRejectsUnrecognizedRequestURI(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)

	action, err := h.server.BeginAuthorization(context.Background(), server.BeginAuthorizationRequest{
		RequestURI: "not-a-request-uri",
		ClientID:   testClientID,
	})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	localErr, ok := action.(server.LocalErrorResponse)
	if !ok {
		t.Fatalf("action = %T, want server.LocalErrorResponse", action)
	}
	if localErr.Error.Code() != server.ErrorInvalidRequest {
		t.Fatalf("Error.Code() = %q, want %q", localErr.Error.Code(), server.ErrorInvalidRequest)
	}
}

func TestBeginAuthorizationRejectsMissingClientID(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	pushResult, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: plainFormParameters(t, h.clientAssertion(t), nil)},
	})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}

	action, err := h.server.BeginAuthorization(context.Background(), server.BeginAuthorizationRequest{
		RequestURI: pushResult.RequestURI.String(),
		ClientID:   "",
	})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	localErr, ok := action.(server.LocalErrorResponse)
	if !ok {
		t.Fatalf("action = %T, want server.LocalErrorResponse", action)
	}
	if localErr.Error.Code() != server.ErrorInvalidRequest {
		t.Fatalf("Error.Code() = %q, want %q", localErr.Error.Code(), server.ErrorInvalidRequest)
	}
}

func TestBeginAuthorizationRejectsClientIDMismatch(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	pushResult, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: plainFormParameters(t, h.clientAssertion(t), nil)},
	})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}

	action, err := h.server.BeginAuthorization(context.Background(), server.BeginAuthorizationRequest{
		RequestURI: pushResult.RequestURI.String(),
		ClientID:   "different-client",
	})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	localErr, ok := action.(server.LocalErrorResponse)
	if !ok {
		t.Fatalf("action = %T, want server.LocalErrorResponse", action)
	}
	if localErr.Error.Code() != server.ErrorInvalidRequestURI {
		t.Fatalf("Error.Code() = %q, want %q", localErr.Error.Code(), server.ErrorInvalidRequestURI)
	}
}

// TestBeginAuthorizationRequestURIRepeatsUntilAuthorizationCompletes
// covers FAPI 2.0 Security Profile 5.3.2.2 Note 3: an authorization
// server enforcing one-time use of request_uri must do so at the point
// of authorization, not at the point of visiting the authorization
// endpoint — so revisiting /authorize with the same request_uri before
// ever completing the interaction (e.g. the browser reloading, or
// being sent back before authenticating) must succeed each time, not
// just once.
func TestBeginAuthorizationRequestURIRepeatsUntilAuthorizationCompletes(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	pushResult, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: plainFormParameters(t, h.clientAssertion(t), nil)},
	})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}

	beginReq := server.BeginAuthorizationRequest{RequestURI: pushResult.RequestURI.String(), ClientID: testClientID}
	first, err := h.server.BeginAuthorization(context.Background(), beginReq)
	if err != nil {
		t.Fatalf("first BeginAuthorization: %v", err)
	}
	firstInteraction, ok := first.(server.InteractionRequired)
	if !ok {
		t.Fatalf("first action = %T, want InteractionRequired", first)
	}

	second, err := h.server.BeginAuthorization(context.Background(), beginReq)
	if err != nil {
		t.Fatalf("second BeginAuthorization: %v", err)
	}
	secondInteraction, ok := second.(server.InteractionRequired)
	if !ok {
		t.Fatalf("second action = %T, want InteractionRequired", second)
	}
	if firstInteraction.Handle == secondInteraction.Handle {
		t.Fatalf("first and second BeginAuthorization produced the same handle")
	}
}

// TestBeginAuthorizationRequestURIFailsAfterAuthorizationCompletes
// covers the other half of FAPI 2.0 Security Profile 5.3.2.2 Note 3:
// once an interaction minted from a request_uri actually completes,
// that request_uri is consumed — a further visit to /authorize with it
// must fail, even though earlier visits (before completion) succeeded.
func TestBeginAuthorizationRequestURIFailsAfterAuthorizationCompletes(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	pushResult, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: plainFormParameters(t, h.clientAssertion(t), nil)},
	})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}

	beginReq := server.BeginAuthorizationRequest{RequestURI: pushResult.RequestURI.String(), ClientID: testClientID}
	first, err := h.server.BeginAuthorization(context.Background(), beginReq)
	if err != nil {
		t.Fatalf("first BeginAuthorization: %v", err)
	}
	interaction, ok := first.(server.InteractionRequired)
	if !ok {
		t.Fatalf("first action = %T, want InteractionRequired", first)
	}

	if _, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
		Handle: interaction.Handle, Result: authorizeResult(t),
	}); err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}

	third, err := h.server.BeginAuthorization(context.Background(), beginReq)
	if err != nil {
		t.Fatalf("third BeginAuthorization: %v", err)
	}
	localErr, ok := third.(server.LocalErrorResponse)
	if !ok {
		t.Fatalf("third action = %T, want server.LocalErrorResponse", third)
	}
	if localErr.Error.Code() != server.ErrorInvalidRequestURI {
		t.Fatalf("Error.Code() = %q, want %q", localErr.Error.Code(), server.ErrorInvalidRequestURI)
	}
}

func TestBeginAuthorizationAuditsOutcomes(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	pushAndBegin(t, h, nil)

	var success, failure int
	for _, e := range h.audit.all() {
		if e.Type != server.AuditEventBeginAuthorization {
			continue
		}
		if e.Outcome == server.AuditOutcomeSuccess {
			success++
		} else {
			failure++
		}
	}
	if success != 1 || failure != 0 {
		t.Fatalf("BeginAuthorization audit events: success=%d failure=%d, want success=1 failure=0", success, failure)
	}

	if _, err := h.server.BeginAuthorization(context.Background(), server.BeginAuthorizationRequest{
		RequestURI: "not-a-request-uri", ClientID: testClientID,
	}); err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	failure = 0
	for _, e := range h.audit.all() {
		if e.Type == server.AuditEventBeginAuthorization && e.Outcome == server.AuditOutcomeFailure {
			failure++
		}
	}
	if failure != 1 {
		t.Fatalf("failure audit events = %d, want 1", failure)
	}
}

// --- expiry test, using a mutable clock -------------------------------

type stepClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *stepClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *stepClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func TestBeginAuthorizationRejectsExpiredRequestURI(t *testing.T) {
	key := generateKey(t)
	client, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID:                       testClientID,
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
	clock := &stepClock{now: time.Now()}

	srv, err := server.New(server.Config{
		Issuer:    issuer,
		Endpoints: testEndpoints(t),
		Profile:   server.ProfileFAPISecurity,
		Algorithms: server.AlgorithmPolicy{
			ClientAssertion: server.AlgorithmSet{fapi.ES256},
			RequestObject:   server.AlgorithmSet{fapi.ES256},
			AccessToken:     fapi.ES256,
			IDToken:         fapi.ES256,
		},
		Limits: server.Limits{
			PushedRequestLifetime:      90 * time.Second,
			MaxClientAssertionLifetime: time.Minute,
			MaxRequestObjectLifetime:   time.Minute,
			InteractionLifetime:        5 * time.Minute,
			AuthorizationCodeLifetime:  time.Minute,
			AccessTokenLifetime:        5 * time.Minute,
			IDTokenLifetime:            5 * time.Minute,
			RefreshTokenLifetime:       5 * time.Minute,
			MaxDPoPProofAge:            time.Minute,
			MaxClockSkew:               5 * time.Second,
		},
		Assurance: server.AssuranceDevelopment,
	}, server.Dependencies{
		Clients:      &fakeClientRepository{clients: map[fapi.ClientID]storage.RegisteredClient{testClientID: client}},
		Transactions: &fakeTransactionStore{},
		Grants:       &fakeGrantStore{},
		Replay:       &fakeReplayStore{},
		ClientKeys: &fakeClientKeySource{keysByClient: map[fapi.ClientID][]keys.VerificationKey{
			testClientID: {{Algorithm: fapi.ES256, PublicKey: &key.PublicKey}},
		}},
		Keys:   &fakeKeyManager{key: generateKey(t), keyID: "as-key-1"},
		Clock:  clock,
		Random: rand.Reader,
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	assertion, err := clientassertion.CreateAssertion(clientassertion.AssertionRequest{
		Signer: key, Algorithm: fapi.ES256,
		ClientID: testClientID.String(), Audience: testIssuer,
		Now: clock.Now(), Lifetime: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("CreateAssertion: %v", err)
	}
	pushResult, err := srv.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: plainFormParameters(t, assertion, nil)},
	})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}

	clock.advance(91 * time.Second) // past the 90s PushedRequestLifetime

	action, err := srv.BeginAuthorization(context.Background(), server.BeginAuthorizationRequest{
		RequestURI: pushResult.RequestURI.String(),
		ClientID:   testClientID,
	})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	localErr, ok := action.(server.LocalErrorResponse)
	if !ok {
		t.Fatalf("action = %T, want server.LocalErrorResponse", action)
	}
	if localErr.Error.Code() != server.ErrorInvalidRequestURI {
		t.Fatalf("Error.Code() = %q, want %q", localErr.Error.Code(), server.ErrorInvalidRequestURI)
	}
}

// TestBuildAuthorizationErrorRedirect covers the escape hatch a caller
// (e.g. a conformance test harness) uses to present a validation
// failure BeginAuthorization could only otherwise express as
// LocalErrorResponse as a genuine redirect instead — see its doc
// comment for why. This only checks the plain-profile query-parameter
// path; ProfileFAPISecurityWithMessageSigning's JARM-signed path is
// already covered by buildAuthorizationResponse's other callers
// (e.g. TestCompleteAuthorizationSuccessMessageSigningProfile).
func TestBuildAuthorizationErrorRedirect(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)

	dest, err := h.server.BuildAuthorizationErrorRedirect(context.Background(), testClientID, testRedirectURI, "xyz-state", "invalid_request_uri", "request_uri is invalid, expired, or already used")
	if err != nil {
		t.Fatalf("BuildAuthorizationErrorRedirect: %v", err)
	}

	destURL := dest.URL()
	q := destURL.Query()
	if got := q.Get("error"); got != "invalid_request_uri" {
		t.Fatalf("error = %q, want invalid_request_uri", got)
	}
	if got := q.Get("error_description"); got != "request_uri is invalid, expired, or already used" {
		t.Fatalf("error_description = %q, want the given description", got)
	}
	if got := q.Get("state"); got != "xyz-state" {
		t.Fatalf("state = %q, want xyz-state", got)
	}
	if destURL.Scheme != "https" || destURL.Host != "rp.example" || destURL.Path != "/callback" {
		t.Fatalf("destination = %q, want to start with %q", dest.String(), testRedirectURI)
	}
}

// TestBuildAuthorizationErrorRedirectOmitsEmptyState confirms an empty
// state is simply left out of the response rather than sent as
// state="" — matching plain redirect behavior elsewhere in this
// package (see completeErrorRedirect's own params map, which this
// method delegates to).
func TestBuildAuthorizationErrorRedirectOmitsEmptyState(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)

	dest, err := h.server.BuildAuthorizationErrorRedirect(context.Background(), testClientID, testRedirectURI, "", "invalid_request", "missing request_object")
	if err != nil {
		t.Fatalf("BuildAuthorizationErrorRedirect: %v", err)
	}
	destURL := dest.URL()
	if _, present := destURL.Query()["state"]; present {
		t.Fatalf("state parameter present in response, want omitted for empty state")
	}
}

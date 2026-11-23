package server_test

import (
	"context"
	"encoding/json"
	"flag"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/federation"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/server"
)

// hookPanicChildEnv makes TestAutomaticRegistrationHookPanicChild run,
// as TestAutomaticRegistrationHookPanicAnswersServerError's child.
const hookPanicChildEnv = "FAPIGO_TEST_AUTOMATIC_REGISTRATION_HOOK_PANIC_CHILD"

// runChildTest runs this test binary's test name alone in a child
// process, with env added to its environment, and fails t unless it
// passes. What the child covers is collected with this run's coverage.
func runChildTest(t *testing.T, name string, env ...string) {
	t.Helper()
	args := []string{"-test.run=^" + name + "$", "-test.v", "-test.count=1", "-test.timeout=2m"}
	if dir := flag.Lookup("test.gocoverdir"); dir != nil && dir.Value.String() != "" {
		args = append(args, "-test.gocoverdir="+dir.Value.String())
	}
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "--- PASS: "+name) {
		t.Fatalf("child %s (%s): %v\n%s", name, strings.Join(env, " "), err, out)
	}
}

// TestAutomaticRegistrationHookPanicAnswersServerError runs
// TestAutomaticRegistrationHookPanicChild in a child process: a panic
// the server didn't contain would end the child, whatever its HTTP
// layer recovers, not this test binary.
func TestAutomaticRegistrationHookPanicAnswersServerError(t *testing.T) {
	if os.Getenv(hookPanicChildEnv) == "1" {
		t.Skip("running as the child")
	}
	runChildTest(t, "TestAutomaticRegistrationHookPanicChild", hookPanicChildEnv+"=1")
}

// TestAutomaticRegistrationHookPanicChild: a production server whose
// AutomaticRegistration.OnResolutionFailure panics, served over HTTP
// behind an embedder's recovery middleware. An unauthenticated pushed
// authorization request naming an Entity Identifier that doesn't
// resolve, by client_id alone or with an assertion signed with any key,
// is answered 500 server_error by the server itself: the panic never
// reaches the middleware, and the server keeps serving. The failure the
// hook was told about is remembered, so the same client_id is answered
// invalid_client next.
func TestAutomaticRegistrationHookPanicChild(t *testing.T) {
	if os.Getenv(hookPanicChildEnv) != "1" {
		t.Skip("only runs as TestAutomaticRegistrationHookPanicAnswersServerError's child")
	}
	srv := newHookPanicServer(t)
	var recovered atomic.Int32
	ts := httptest.NewServer(recoverPanics(&recovered, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, err := server.PushAuthorizationRequestFromHTTP(r)
		if err != nil {
			server.WriteError(w, err)
			return
		}
		res, err := srv.PushAuthorizationRequest(r.Context(), req)
		if err != nil {
			server.WriteError(w, err)
			return
		}
		res.WriteJSON(w)
	})))
	defer ts.Close()

	// The production fetcher refuses an IP literal before dialing, so
	// each resolution fails without leaving the host.
	const bare, signed = "https://127.0.0.1/rp", "https://127.0.0.1/other-rp"
	for _, step := range []struct {
		form   url.Values
		status int
		code   server.ErrorCode
	}{
		{url.Values{"client_id": {bare}}, http.StatusInternalServerError, server.ErrorServerError},
		{url.Values{"client_id": {bare}}, http.StatusUnauthorized, server.ErrorInvalidClient},
		{assertionForm(t, signed), http.StatusInternalServerError, server.ErrorServerError},
	} {
		status, code := postForm(t, ts.URL, step.form)
		if status != step.status || code != step.code {
			t.Fatalf("POST %v = %d %q, want %d %q", step.form, status, code, step.status, step.code)
		}
	}
	if n := recovered.Load(); n != 0 {
		t.Fatalf("the HTTP layer recovered %d panics, want none: the server answers for itself", n)
	}
}

// newHookPanicServer is a production server with automatic registration
// on, fetching through a production fapihttp client, whose
// OnResolutionFailure panics.
func newHookPanicServer(t *testing.T) *server.Server {
	t.Helper()
	cfg := validConfig(t)
	asProduction(&cfg)
	cfg.Deployment = server.DeploymentSingleInstance
	cfg.AutomaticRegistration = server.AutomaticRegistrationConfig{
		TrustAnchors:         []federation.TrustAnchor{{EntityID: "https://ta.example", JWKS: fedJWKS(t, "ta", generateKey(t))}},
		AllowedScopes:        []string{"openid", "accounts"},
		MaxPathLength:        5,
		MaxAuthorityHints:    5,
		MaxStatementLifetime: 2 * time.Hour,
		MaxClockSkew:         5 * time.Second,
		MaxCacheAge:          time.Hour,
		OnResolutionFailure:  func(context.Context, fapi.ClientID, error) { panic("embedder hook bug") },
	}
	transport, err := fapihttp.NewClient(fapihttp.RecommendedTransportConfig())
	if err != nil {
		t.Fatalf("fapihttp.NewClient: %v", err)
	}
	fetcher, err := fapihttp.New(transport, fapihttp.RecommendedConfig())
	if err != nil {
		t.Fatalf("fapihttp.New: %v", err)
	}
	deps := validDependencies()
	deps.Audit = &fakeAuditSink{}
	deps.FederationHTTP = fetcher
	srv, err := server.New(cfg, deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return srv
}

// recoverPanics is an embedder's recovery middleware: it answers a
// panic in next 500 and counts it in recovered.
func recoverPanics(recovered *atomic.Int32, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recover() != nil {
				recovered.Add(1)
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// assertionForm is a pushed authorization request authenticated with a
// client assertion for clientID, signed with a key of nobody's.
func assertionForm(t *testing.T, clientID string) url.Values {
	t.Helper()
	assertion, err := clientassertion.CreateAssertion(clientassertion.AssertionRequest{
		Signer: generateKey(t), Algorithm: fapi.ES256, KeyID: "any",
		ClientID: clientID, Audience: testIssuer, Now: time.Now(), Lifetime: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("CreateAssertion: %v", err)
	}
	return url.Values{"client_assertion": {assertion}, "client_assertion_type": {clientassertion.AssertionType}}
}

// postForm posts form to target and returns the status and OAuth error
// code it is answered with.
func postForm(t *testing.T, target string, form url.Values) (int, server.ErrorCode) {
	t.Helper()
	res, err := http.Post(target, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = res.Body.Close() }()
	var body struct {
		Error server.ErrorCode `json:"error"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode the error response: %v", err)
	}
	return res.StatusCode, body.Error
}

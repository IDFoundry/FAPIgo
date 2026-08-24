package client_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/internal/jose"
)

// newResourceTestClient builds a client wired to ts, with everything
// ProtectedResource.Do needs (a DPoP signing key, a real HTTP client).
func newResourceTestClient(t *testing.T, ts *httptest.Server, mutateCfg func(*client.Config)) *client.Client {
	t.Helper()
	cfg := validConfig(t)
	if mutateCfg != nil {
		mutateCfg(&cfg)
	}
	deps := validDependencies(t)
	deps.HTTP = ts.Client()
	c, err := client.New(cfg, deps)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	return c
}

// dpopProofClaims decodes a DPoP proof's payload without verifying its
// signature — this test only needs to observe what the client sent
// (htm/htu/ath/nonce), not re-validate signature cryptography
// internal/dpop's own tests already cover.
func dpopProofClaims(t *testing.T, proof string) map[string]any {
	t.Helper()
	compact, err := jose.ParseCompact(proof)
	if err != nil {
		t.Fatalf("parse DPoP proof: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(compact.Payload, &claims); err != nil {
		t.Fatalf("unmarshal DPoP proof claims: %v", err)
	}
	return claims
}

func expectedATH(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestProtectedResourceDoAttachesAuthorizationAndDPoPProof(t *testing.T) {
	const accessToken = "test-access-token"
	var gotAuth, gotProof string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotProof = r.Header.Get("DPoP")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()

	c := newResourceTestClient(t, ts, nil)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/resource?foo=bar", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}

	res, err := c.ProtectedResource(client.TokenSet{AccessToken: fapi.NewSecret(accessToken)}).Do(context.Background(), req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if res.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("status/body = %d/%q, want 200/ok", res.StatusCode, body)
	}

	if gotAuth != "DPoP "+accessToken {
		t.Errorf("Authorization = %q, want %q", gotAuth, "DPoP "+accessToken)
	}
	if gotProof == "" {
		t.Fatalf("DPoP proof header is empty")
	}
	claims := dpopProofClaims(t, gotProof)
	if claims["htm"] != "GET" {
		t.Errorf("htm = %v, want GET", claims["htm"])
	}
	// RFC 9449 §4.2: htu excludes query and fragment.
	if want := ts.URL + "/resource"; claims["htu"] != want {
		t.Errorf("htu = %v, want %q (query stripped)", claims["htu"], want)
	}
	if claims["ath"] != expectedATH(accessToken) {
		t.Errorf("ath = %v, want %q", claims["ath"], expectedATH(accessToken))
	}
	if _, ok := claims["nonce"]; ok {
		t.Errorf("nonce claim present on a request with no prior challenge: %v", claims["nonce"])
	}
}

func TestProtectedResourceDoRetriesOnNonceChallenge(t *testing.T) {
	const serverNonce = "server-nonce-1"
	var mu sync.Mutex
	var calls int
	var secondProofNonce string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		call := calls
		mu.Unlock()
		if call == 1 {
			w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce", error_description="nonce required"`)
			w.Header().Set("DPoP-Nonce", serverNonce)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		claims := dpopProofClaims(t, r.Header.Get("DPoP"))
		if nonce, _ := claims["nonce"].(string); nonce != "" {
			secondProofNonce = nonce
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()

	c := newResourceTestClient(t, ts, nil)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/resource", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	res, err := c.ProtectedResource(client.TokenSet{AccessToken: fapi.NewSecret("test-access-token")}).Do(context.Background(), req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 after retry", res.StatusCode)
	}
	mu.Lock()
	gotCalls := calls
	mu.Unlock()
	if gotCalls != 2 {
		t.Fatalf("server received %d requests, want exactly 2 (initial + one retry)", gotCalls)
	}
	if secondProofNonce != serverNonce {
		t.Errorf("retry proof nonce = %q, want %q", secondProofNonce, serverNonce)
	}
}

// TestProtectedResourceDoDoesNotRetryOnBareNonceHeader confirms Do
// requires the WWW-Authenticate challenge itself, not just a DPoP-Nonce
// header — mirroring the token endpoint's own isDPoPNonceError
// discipline (a server may send DPoP-Nonce unprompted, e.g. to
// pre-seed a caller's next request, without it being a challenge to
// retry against).
func TestProtectedResourceDoDoesNotRetryOnBareNonceHeader(t *testing.T) {
	var mu sync.Mutex
	var calls int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		w.Header().Set("DPoP-Nonce", "pre-seeded-nonce")
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()

	c := newResourceTestClient(t, ts, nil)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/resource", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	res, err := c.ProtectedResource(client.TokenSet{AccessToken: fapi.NewSecret("test-access-token")}).Do(context.Background(), req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (returned as-is, not retried)", res.StatusCode)
	}
	mu.Lock()
	gotCalls := calls
	mu.Unlock()
	if gotCalls != 1 {
		t.Fatalf("server received %d requests, want exactly 1 (no retry)", gotCalls)
	}
}

func TestProtectedResourceDoBoundsResponseBodySize(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bytes.Repeat([]byte("x"), 1024))
	}))
	defer ts.Close()

	c := newResourceTestClient(t, ts, func(cfg *client.Config) {
		cfg.Limits.MaxHTTPResponseBytes = 4
	})
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/resource", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	if _, err := c.ProtectedResource(client.TokenSet{AccessToken: fapi.NewSecret("test-access-token")}).Do(context.Background(), req); err == nil {
		t.Fatalf("Do(oversized response) = nil error, want error")
	}
}

func TestProtectedResourceDoRejectsNilRequest(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	c := newResourceTestClient(t, ts, nil)
	if _, err := c.ProtectedResource(client.TokenSet{AccessToken: fapi.NewSecret("test-access-token")}).Do(context.Background(), nil); err == nil {
		t.Fatalf("Do(nil request) = nil error, want error")
	}
}

// TestProtectedResourceDoRejectsUnreplayableBodyOnRetry confirms Do
// fails closed — rather than silently sending an empty or truncated
// body — when the resource server challenges for a nonce but the
// request body can't be safely resent.
func TestProtectedResourceDoRejectsUnreplayableBodyOnRetry(t *testing.T) {
	var mu sync.Mutex
	var calls int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
		w.Header().Set("DPoP-Nonce", "server-nonce")
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()

	c := newResourceTestClient(t, ts, nil)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, ts.URL+"/resource", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	// Attach a body without a GetBody — http.NewRequestWithContext only
	// sets GetBody automatically for the body types it recognizes, and a
	// bare io.NopCloser isn't one of them.
	req.Body = io.NopCloser(strings.NewReader("payload"))
	req.ContentLength = int64(len("payload"))

	if _, err := c.ProtectedResource(client.TokenSet{AccessToken: fapi.NewSecret("test-access-token")}).Do(context.Background(), req); err == nil {
		t.Fatalf("Do(unreplayable body, nonce challenge) = nil error, want error")
	}
	mu.Lock()
	gotCalls := calls
	mu.Unlock()
	if gotCalls != 1 {
		t.Fatalf("server received %d requests, want exactly 1 (retry must not be attempted)", gotCalls)
	}
}

// TestProtectedResourceDoRetriesReplayableBody confirms a POST body
// built through http.NewRequestWithContext (which sets GetBody for a
// *bytes.Reader) survives the nonce-challenge retry intact.
func TestProtectedResourceDoRetriesReplayableBody(t *testing.T) {
	const payload = "the-request-payload"
	var mu sync.Mutex
	var calls int
	var bodies []string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		mu.Lock()
		calls++
		call := calls
		bodies = append(bodies, string(body))
		mu.Unlock()
		if call == 1 {
			w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
			w.Header().Set("DPoP-Nonce", "server-nonce")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	c := newResourceTestClient(t, ts, nil)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, ts.URL+"/resource", bytes.NewReader([]byte(payload)))
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	res, err := c.ProtectedResource(client.TokenSet{AccessToken: fapi.NewSecret("test-access-token")}).Do(context.Background(), req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 after retry", res.StatusCode)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 2 || bodies[0] != payload || bodies[1] != payload {
		t.Fatalf("server-observed bodies = %v, want [%q %q]", bodies, payload, payload)
	}
}

func TestProtectedResourceDoPropagatesHTTPFailure(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	ts.Close() // closed before use: every request now fails to connect

	c := newResourceTestClient(t, ts, nil)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/resource", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	if _, err := c.ProtectedResource(client.TokenSet{AccessToken: fapi.NewSecret("test-access-token")}).Do(context.Background(), req); err == nil {
		t.Fatalf("Do(unreachable server) = nil error, want error")
	}
}

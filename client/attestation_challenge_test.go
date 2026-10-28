package client_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/internal/clientattestation"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/storage"
)

// challengingAS is an authorization server that requires attestation
// Challenges (draft-12 §6): a request whose PoP doesn't carry the
// current Challenge is answered 400 use_attestation_challenge with a
// fresh one in OAuth-Client-Attestation-Challenge (§6.1). rotate, if
// set, also sends a new Challenge on every successful response (§6.2),
// and always makes every request fail with a new Challenge, to check
// the client retries only once.
type challengingAS struct {
	t *testing.T

	mu        sync.Mutex
	current   string
	issued    int
	rotate    bool
	always    bool
	dpopNonce string // also sent on the challenge error, if set
	// pollPending answers the token endpoint authorization_pending, for
	// a CIBA poll: its openid request would need an ID token otherwise.
	pollPending bool

	requests   int
	challenges []string // each request's PoP challenge claim, in order
	dpopNonces []string // each request's DPoP proof nonce claim, in order
}

func (a *challengingAS) newChallenge() string {
	a.issued++
	a.current = fmt.Sprintf("challenge-%d", a.issued)
	return a.current
}

func (a *challengingAS) handler(success func(w http.ResponseWriter)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		a.requests++
		challenge := popChallenge(a.t, r.Header.Get("OAuth-Client-Attestation-PoP"))
		a.challenges = append(a.challenges, challenge)
		a.dpopNonces = append(a.dpopNonces, proofNonce(a.t, r.Header.Get("DPoP")))
		w.Header().Set("Content-Type", "application/json")
		if a.always || challenge == "" || challenge != a.current {
			w.Header().Set("OAuth-Client-Attestation-Challenge", a.newChallenge())
			if a.dpopNonce != "" {
				w.Header().Set("DPoP-Nonce", a.dpopNonce)
			}
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "use_attestation_challenge"})
			return
		}
		if a.rotate {
			w.Header().Set("OAuth-Client-Attestation-Challenge", a.newChallenge())
		}
		success(w)
	}
}

// popChallenge returns the challenge claim of the PoP compact, "" if it
// has none.
func popChallenge(t *testing.T, compact string) string {
	t.Helper()
	parsed, err := jose.ParseCompact(compact)
	if err != nil {
		t.Fatalf("PoP: %v", err)
	}
	var claims struct {
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(parsed.Payload, &claims); err != nil {
		t.Fatalf("PoP claims: %v", err)
	}
	return claims.Challenge
}

// proofNonce returns the nonce claim of the DPoP proof compact, "" for
// none or no proof.
func proofNonce(t *testing.T, compact string) string {
	t.Helper()
	if compact == "" {
		return ""
	}
	parsed, err := jose.ParseCompact(compact)
	if err != nil {
		t.Fatalf("DPoP proof: %v", err)
	}
	var claims struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(parsed.Payload, &claims); err != nil {
		t.Fatalf("DPoP proof claims: %v", err)
	}
	return claims.Nonce
}

func writePendingResponse(w http.ResponseWriter) {
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": "authorization_pending"})
}

func writeTokenResponse(w http.ResponseWriter) {
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": "opaque-access-token", "token_type": "DPoP", "expires_in": 300, "scope": "accounts",
	})
}

func writeMTLSTokenResponse(w http.ResponseWriter) {
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": "opaque-access-token", "token_type": "Bearer", "expires_in": 300, "scope": "accounts",
	})
}

func writeBackchannelResponse(w http.ResponseWriter) {
	_ = json.NewEncoder(w).Encode(map[string]any{"auth_req_id": "test-auth-req-id", "expires_in": 120, "interval": 5})
}

func writePARResponse(w http.ResponseWriter) {
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{"request_uri": "urn:ietf:params:oauth:request_uri:abc123", "expires_in": 60})
}

// newChallengedClient is a client authenticating by attestation against
// as, with source as its AttestationSource and tweak, if non-nil,
// adjusting its configuration.
func newChallengedClient(t *testing.T, as *challengingAS, source client.AttestationSource, tweak func(*client.Config)) *client.Client {
	t.Helper()
	mux := http.NewServeMux()
	tokenResponse := writeTokenResponse
	cfg := validConfig(t)
	if tweak != nil {
		tweak(&cfg)
	}
	if cfg.SenderConstrain == storage.SenderConstrainMTLS {
		tokenResponse = writeMTLSTokenResponse
	}
	if as.pollPending {
		tokenResponse = writePendingResponse
	}
	mux.HandleFunc("/token", as.handler(tokenResponse))
	mux.HandleFunc("/par", as.handler(writePARResponse))
	mux.HandleFunc("/revoke", as.handler(func(w http.ResponseWriter) { w.WriteHeader(http.StatusOK) }))
	mux.HandleFunc("/backchannel-authenticate", as.handler(writeBackchannelResponse))
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	cfg.ClientAuthMethod = storage.ClientAuthMethodAttestation
	cfg.Algorithms.ClientAuthentication = 0
	cfg.Limits.ClientAssertionLifetime = 0
	cfg.Algorithms.ClientAttestationPoP = fapi.ES256
	cfg.Algorithms.BackchannelAuthenticationRequest = fapi.ES256
	cfg.Limits.BackchannelAuthenticationRequestLifetime = time.Minute
	for path, target := range map[string]*fapi.URL{
		"/token": &cfg.Endpoints.Token, "/par": &cfg.Endpoints.PushedAuthorizationRequest, "/revoke": &cfg.Endpoints.Revocation,
		"/backchannel-authenticate": &cfg.Endpoints.BackchannelAuthentication,
	} {
		u, err := fapi.ParseEndpointURL(ts.URL+path, fapi.AllowLoopbackHTTP())
		if err != nil {
			t.Fatalf("ParseEndpointURL(%s): %v", path, err)
		}
		*target = u
	}
	deps := validDependencies(t)
	deps.HTTP = ts.Client()
	deps.Keys = newFakeKeyManager(t, keys.ClientAttestationPoPSigning, keys.DPoPProofSigning, keys.BackchannelAuthenticationRequestSigning)
	deps.Attestation = source
	c, err := client.New(cfg, deps)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	return c
}

func requestToken(c *client.Client) error {
	_, err := c.RequestClientCredentialsToken(context.Background(), client.ClientCredentialsTokenRequest{Scope: []string{"accounts"}})
	return err
}

// TestAttestationChallengeRetriedOnce: a use_attestation_challenge error
// is retried once, with a new PoP carrying the Challenge it supplied
// (draft-12 §6: "a Client SHOULD retry the request once"); the next
// request carries that same Challenge without a round trip, since it's
// the most recent the server provided.
func TestAttestationChallengeRetriedOnce(t *testing.T) {
	as := &challengingAS{t: t}
	c := newChallengedClient(t, as, fakeAttestationSource{attestation: testAttestationJWT}, nil)
	if err := requestToken(c); err != nil {
		t.Fatalf("first request: %v", err)
	}
	if want := []string{"", "challenge-1"}; fmt.Sprint(as.challenges) != fmt.Sprint(want) {
		t.Fatalf("PoP challenges = %q, want %q", as.challenges, want)
	}
	if err := requestToken(c); err != nil {
		t.Fatalf("second request: %v", err)
	}
	if as.requests != 3 || as.challenges[2] != "challenge-1" {
		t.Fatalf("second request: %d requests, challenges %q; want one more carrying challenge-1", as.requests, as.challenges)
	}
}

// TestAttestationChallengeFromSuccessfulResponse: a Challenge sent on a
// successful response (§6.2) is the one the next PoP carries.
func TestAttestationChallengeFromSuccessfulResponse(t *testing.T) {
	as := &challengingAS{t: t, rotate: true}
	c := newChallengedClient(t, as, fakeAttestationSource{attestation: testAttestationJWT}, nil)
	for range 3 {
		if err := requestToken(c); err != nil {
			t.Fatalf("request: %v", err)
		}
	}
	// One retry for the first request; each later one carries the
	// Challenge the previous response rotated to.
	if want := []string{"", "challenge-1", "challenge-2", "challenge-3"}; fmt.Sprint(as.challenges) != fmt.Sprint(want) {
		t.Fatalf("PoP challenges = %q, want %q", as.challenges, want)
	}
}

// TestAttestationChallengeNotRetriedTwice: "A Client MUST NOT retry
// indefinitely" — a server that answers every request with a new
// Challenge gets two requests, and the client the error.
func TestAttestationChallengeNotRetriedTwice(t *testing.T) {
	as := &challengingAS{t: t, always: true}
	c := newChallengedClient(t, as, fakeAttestationSource{attestation: testAttestationJWT}, nil)
	err := requestToken(c)
	var clientErr *client.Error
	if !errors.As(err, &clientErr) {
		t.Fatalf("err = %v, want a *client.Error", err)
	}
	if resp, ok := clientErr.ServerResponse(); !ok || resp.Code != "use_attestation_challenge" {
		t.Fatalf("err = %v, want the server's use_attestation_challenge", err)
	}
	if as.requests != 2 {
		t.Fatalf("requests = %d, want 2", as.requests)
	}
}

// TestAttestationChallengeRetryKeepsDPoPNonce: the retry's DPoP proof
// carries the server's nonce when the challenge error supplies one, as
// well as the new Challenge.
func TestAttestationChallengeRetryKeepsDPoPNonce(t *testing.T) {
	as := &challengingAS{t: t, dpopNonce: "server-nonce"}
	c := newChallengedClient(t, as, fakeAttestationSource{attestation: testAttestationJWT}, nil)
	if err := requestToken(c); err != nil {
		t.Fatalf("request: %v", err)
	}
	if len(as.dpopNonces) != 2 || as.dpopNonces[1] != "server-nonce" {
		t.Fatalf("DPoP proof nonces = %q, want the retry carrying server-nonce", as.dpopNonces)
	}
}

// TestAttestationChallengeAtEveryEndpoint: the retry applies to PAR
// (with a DPoP proof, and with dpop_jkt), revocation and an mTLS token
// request, as well as a DPoP token request.
func TestAttestationChallengeAtEveryEndpoint(t *testing.T) {
	source := fakeAttestationSource{attestation: testAttestationJWT}
	for name, tc := range map[string]struct {
		tweak func(*client.Config)
		call  func(*client.Client) error
	}{
		"PAR with a DPoP proof": {nil, func(c *client.Client) error {
			_, err := c.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{Scope: []string{"accounts"}})
			return err
		}},
		"PAR with dpop_jkt": {func(cfg *client.Config) { cfg.PARDPoPBinding = client.PARDPoPBindingJKT }, func(c *client.Client) error {
			_, err := c.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{Scope: []string{"accounts"}})
			return err
		}},
		"revocation": {nil, func(c *client.Client) error {
			return c.RevokeToken(context.Background(), refreshTokenSet("refresh-token"))
		}},
		"mTLS token request": {func(cfg *client.Config) { cfg.SenderConstrain = storage.SenderConstrainMTLS }, requestToken},
		"CIBA request":       {nil, beginBackchannel},
		"mTLS CIBA request":  {func(cfg *client.Config) { cfg.SenderConstrain = storage.SenderConstrainMTLS }, beginBackchannel},
	} {
		t.Run(name, func(t *testing.T) {
			as := &challengingAS{t: t}
			c := newChallengedClient(t, as, source, tc.tweak)
			if err := tc.call(c); err != nil {
				t.Fatalf("call: %v", err)
			}
			if want := []string{"", "challenge-1"}; fmt.Sprint(as.challenges) != fmt.Sprint(want) {
				t.Fatalf("PoP challenges = %q, want %q", as.challenges, want)
			}
		})
	}
}

func beginBackchannel(c *client.Client) error {
	_, err := c.BeginBackchannelAuthentication(context.Background(), client.BeginBackchannelAuthenticationRequest{
		Scope: []string{"openid", "accounts"}, LoginHint: "user@example.com",
	})
	return err
}

// TestAttestationChallengeAtCIBAPoll: a CIBA poll is retried once for a
// Challenge too, with DPoP and with mTLS.
func TestAttestationChallengeAtCIBAPoll(t *testing.T) {
	for name, tweak := range map[string]func(*client.Config){
		"DPoP": nil,
		"mTLS": func(cfg *client.Config) { cfg.SenderConstrain = storage.SenderConstrainMTLS },
	} {
		t.Run(name, func(t *testing.T) {
			as := &challengingAS{t: t, pollPending: true}
			c := newChallengedClient(t, as, fakeAttestationSource{attestation: testAttestationJWT}, tweak)
			session, err := c.BeginBackchannelAuthentication(context.Background(), client.BeginBackchannelAuthenticationRequest{
				Scope: []string{"openid", "accounts"}, LoginHint: "user@example.com",
			})
			if err != nil {
				t.Fatalf("BeginBackchannelAuthentication: %v", err)
			}
			as.mu.Lock()
			as.current = "" // demand a new Challenge at the poll
			as.mu.Unlock()
			if _, err := c.PollBackchannelAuthentication(context.Background(), session); err != nil {
				t.Fatalf("PollBackchannelAuthentication: %v", err)
			}
			// Begin: no challenge, then challenge-1. Poll: challenge-1
			// (now refused), then challenge-2.
			if want := []string{"", "challenge-1", "challenge-1", "challenge-2"}; fmt.Sprint(as.challenges) != fmt.Sprint(want) {
				t.Fatalf("PoP challenges = %q, want %q", as.challenges, want)
			}
		})
	}
}

// TestAttestationChallengeSourceUntilServerProvidesOne: a ChallengeSource
// supplies the Challenge until the server has provided one itself; the
// server's most recent then takes over.
func TestAttestationChallengeSourceUntilServerProvidesOne(t *testing.T) {
	as := &challengingAS{t: t}
	source := fakeAttestationSourceWithChallenge{
		fakeAttestationSource: fakeAttestationSource{attestation: testAttestationJWT},
		challenge:             "from-challenge-endpoint",
	}
	c := newChallengedClient(t, as, source, nil)
	if err := requestToken(c); err != nil {
		t.Fatalf("request: %v", err)
	}
	if want := []string{"from-challenge-endpoint", "challenge-1"}; fmt.Sprint(as.challenges) != fmt.Sprint(want) {
		t.Fatalf("PoP challenges = %q, want %q", as.challenges, want)
	}
}

// TestObserveAttestationChallenge: a Challenge from a response the
// embedder received itself reaches the next ClientAttestationHeaders
// PoP; an unusable value, or one for a client that doesn't use
// attestation, is ignored.
func TestObserveAttestationChallenge(t *testing.T) {
	c, _ := newTestClientWithAttestationAuth(t)
	popChallengeOf := func() string {
		t.Helper()
		_, popCompact, err := c.ClientAttestationHeaders(context.Background())
		if err != nil {
			t.Fatalf("ClientAttestationHeaders: %v", err)
		}
		if _, err := clientattestation.ParsePoP(popCompact); err != nil {
			t.Fatalf("ParsePoP: %v", err)
		}
		return popChallenge(t, popCompact)
	}
	header := func(value string) http.Header {
		h := http.Header{}
		if value != "" {
			h.Set("OAuth-Client-Attestation-Challenge", value)
		}
		return h
	}
	if got := popChallengeOf(); got != "" {
		t.Fatalf("challenge before any = %q", got)
	}
	c.ObserveAttestationChallenge(header("observed-1"))
	if got := popChallengeOf(); got != "observed-1" {
		t.Fatalf("challenge = %q, want observed-1", got)
	}
	for _, unusable := range []string{"", "has space", "tab\tin", strings.Repeat("a", 1025), "non-ascii-\u00e9"} {
		c.ObserveAttestationChallenge(header(unusable))
		if got := popChallengeOf(); got != "observed-1" {
			t.Fatalf("after unusable %q: challenge = %q, want observed-1 kept", unusable, got)
		}
	}
	c.ObserveAttestationChallenge(header(strings.Repeat("a", 1024)))
	if got := popChallengeOf(); len(got) != 1024 {
		t.Fatalf("a 1024-byte challenge wasn't kept: len %d", len(got))
	}
}

// TestObserveAttestationChallengeIgnoredWithoutAttestation: a client
// that doesn't authenticate by attestation keeps no Challenge.
func TestObserveAttestationChallengeIgnoredWithoutAttestation(t *testing.T) {
	cfg := validConfig(t)
	c, err := client.New(cfg, validDependencies(t))
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	h := http.Header{}
	h.Set("OAuth-Client-Attestation-Challenge", "observed")
	c.ObserveAttestationChallenge(h) // no effect, no panic
	if _, _, err := c.ClientAttestationHeaders(context.Background()); err == nil {
		t.Fatal("ClientAttestationHeaders for a non-attestation client succeeded")
	}
}

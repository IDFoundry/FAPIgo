package client_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/storage"
)

// TestBeginAuthorizationPropagatesTransportFailureOnPARPlain covers
// pushAuthorizationRequestPlain's (SenderConstrainMTLS) transport-failure
// branch — a connection failure at PAR, as opposed to an HTTP-level
// error response.
func TestBeginAuthorizationPropagatesTransportFailureOnPARPlain(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	ts.Close() // closed before use: every request now fails to connect

	cfg := validConfig(t)
	cfg.SenderConstrain = storage.SenderConstrainMTLS
	cfg.Algorithms.DPoP = 0
	parURL, err := fapi.ParseEndpointURL(ts.URL+"/par", fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseEndpointURL(par): %v", err)
	}
	cfg.Endpoints.PushedAuthorizationRequest = parURL

	deps := validDependencies(t)
	deps.HTTP = ts.Client()

	c, err := client.New(cfg, deps)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	if _, err := c.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{Scope: []string{"openid"}}); err == nil {
		t.Fatalf("BeginAuthorization(MTLS PAR transport failure) = nil error, want error")
	}
}

// TestBeginAuthorizationPropagatesTransportFailureOnPARWithJKT covers
// pushAuthorizationRequestWithJKT's transport-failure branch.
func TestBeginAuthorizationPropagatesTransportFailureOnPARWithJKT(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	ts.Close() // closed before use: every request now fails to connect

	cfg := validConfig(t)
	cfg.PARDPoPBinding = client.PARDPoPBindingJKT
	parURL, err := fapi.ParseEndpointURL(ts.URL+"/par", fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseEndpointURL(par): %v", err)
	}
	cfg.Endpoints.PushedAuthorizationRequest = parURL

	deps := validDependencies(t)
	deps.HTTP = ts.Client()

	c, err := client.New(cfg, deps)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	if _, err := c.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{Scope: []string{"openid"}}); err == nil {
		t.Fatalf("BeginAuthorization(dpop_jkt PAR transport failure) = nil error, want error")
	}
}

// TestBeginAuthorizationPropagatesTransportFailureOnPARWithDPoPProof
// covers pushAuthorizationRequestWithDPoPProof's initial-attempt
// transport-failure branch (PARDPoPBindingProof, the default).
func TestBeginAuthorizationPropagatesTransportFailureOnPARWithDPoPProof(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	ts.Close() // closed before use: every request now fails to connect

	cfg := validConfig(t)
	parURL, err := fapi.ParseEndpointURL(ts.URL+"/par", fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseEndpointURL(par): %v", err)
	}
	cfg.Endpoints.PushedAuthorizationRequest = parURL

	deps := validDependencies(t)
	deps.HTTP = ts.Client()

	c, err := client.New(cfg, deps)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	if _, err := c.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{Scope: []string{"openid"}}); err == nil {
		t.Fatalf("BeginAuthorization(PAR transport failure) = nil error, want error")
	}
}

// TestBeginAuthorizationPropagatesTransportFailureOnPARRetry covers
// pushAuthorizationRequestWithDPoPProof's retry-attempt transport-failure
// branch: the initial PAR call succeeds far enough to receive a
// use_dpop_nonce challenge, but the replay carrying the fresh nonce
// fails at the transport level.
func TestBeginAuthorizationPropagatesTransportFailureOnPARRetry(t *testing.T) {
	as := newFakeAS(t, testIssuer, false)
	ts := httptest.NewServer(as.handler())
	t.Cleanup(ts.Close)
	as.challengeParDPoPNonce = "server-issued-par-nonce"

	cfg := validConfig(t)
	parURL, err := fapi.ParseEndpointURL(ts.URL+"/par", fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseEndpointURL(par): %v", err)
	}
	cfg.Endpoints.PushedAuthorizationRequest = parURL

	deps := validDependencies(t)
	deps.HTTP = &failNthRequestHTTPClient{real: ts.Client(), pathSuffix: "/par", failOn: 2}

	c, err := client.New(cfg, deps)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	if _, err := c.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{Scope: []string{"openid"}}); err == nil {
		t.Fatalf("BeginAuthorization(PAR retry transport failure) = nil error, want error")
	}
	if as.parCallCount != 1 {
		t.Fatalf("parCallCount = %d, want 1 (the retry failed at the transport, never reaching the fake AS)", as.parCallCount)
	}
}

// TestBeginAuthorizationRejectsMalformedPARResponse: a 201 PAR response
// that isn't RFC 9126 §2.2's request_uri and positive expires_in is
// invalid_response, and no session is created for it.
func TestBeginAuthorizationRejectsMalformedPARResponse(t *testing.T) {
	for name, body := range map[string]string{
		"not JSON":       `{"request_uri":`,
		"no request_uri": `{"expires_in":60}`,
		"no expires_in":  `{"request_uri":"urn:ietf:params:oauth:request_uri:abc123"}`,
	} {
		t.Run(name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(body))
			}))
			t.Cleanup(ts.Close)
			cfg := validConfig(t)
			parURL, err := fapi.ParseEndpointURL(ts.URL+"/par", fapi.AllowLoopbackHTTP())
			if err != nil {
				t.Fatalf("ParseEndpointURL(par): %v", err)
			}
			cfg.Endpoints.PushedAuthorizationRequest = parURL
			deps := validDependencies(t)
			deps.HTTP = ts.Client()
			sessions := newFakeSessionStore()
			deps.Sessions = sessions
			c, err := client.New(cfg, deps)
			if err != nil {
				t.Fatalf("client.New: %v", err)
			}
			_, err = c.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{Scope: []string{"openid"}})
			var cerr *client.Error
			if !errors.As(err, &cerr) || cerr.Code() != client.ErrorInvalidResponse {
				t.Fatalf("BeginAuthorization(%s) = %v, want invalid_response", name, err)
			}
			if len(sessions.sessions) != 0 {
				t.Errorf("%d sessions created, want none", len(sessions.sessions))
			}
		})
	}
}

package client_test

import (
	"context"
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

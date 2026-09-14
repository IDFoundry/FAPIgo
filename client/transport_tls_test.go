package client_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/idfoundry/fapigo/fapihttp"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
)

// strippedTLSHTTPClient wraps a real *http.Client and clears every
// response's TLS field before returning it — simulating a
// round-tripper that silently didn't use TLS at all (a stripped
// corporate proxy, a misconfigured custom Transport), the one failure
// mode postForm's own TLS assertion catches.
type strippedTLSHTTPClient struct {
	real *http.Client
}

func (c strippedTLSHTTPClient) Do(req *http.Request) (*http.Response, error) {
	res, err := c.real.Do(req)
	if err != nil {
		return nil, err
	}
	res.TLS = nil
	return res, nil
}

// newTLSTestConfig spins up a real TLS httptest.Server serving the
// same fake PAR/token endpoints newTestClient uses, and returns a
// Config already pointing at it — for tests that construct more than
// one Client against the identical endpoints with a different
// Dependencies.HTTP, to isolate postForm's own TLS assertion from
// every other construction concern.
func newTLSTestConfig(t *testing.T) (client.Config, *httptest.Server) {
	t.Helper()
	as := newFakeAS(t, testIssuer, false)
	ts := httptest.NewTLSServer(as.handler())
	t.Cleanup(ts.Close)

	cfg := validConfig(t)
	parURL, err := fapi.ParseEndpointURL(ts.URL + "/par")
	if err != nil {
		t.Fatalf("ParseEndpointURL(par): %v", err)
	}
	tokenURL, err := fapi.ParseEndpointURL(ts.URL + "/token")
	if err != nil {
		t.Fatalf("ParseEndpointURL(token): %v", err)
	}
	cfg.Endpoints.PushedAuthorizationRequest = parURL
	cfg.Endpoints.Token = tokenURL
	return cfg, ts
}

// TestBeginAuthorizationSucceedsOverRealTLS confirms postForm's TLS
// assertion never false-positives on a legitimately TLS-backed PAR
// call — the base case TestBeginAuthorizationRejectsStrippedTLS is
// contrasted against.
func TestBeginAuthorizationSucceedsOverRealTLS(t *testing.T) {
	cfg, ts := newTLSTestConfig(t)
	deps := validDependencies(t)
	deps.HTTP = ts.Client()

	c, err := client.New(cfg, deps)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	if _, err := c.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{Scope: []string{"openid"}}); err != nil {
		t.Fatalf("BeginAuthorization over real TLS: %v", err)
	}
}

// TestBeginAuthorizationRejectsStrippedTLS covers postForm's own TLS
// assertion: a round-tripper that completes an https request but
// leaves the response's TLS field nil (as a stripping proxy or a
// misconfigured custom Transport would) is rejected with
// fapihttp.ErrMissingTLS — the same backstop fapihttp.Client already
// applies to discovery/JWKS fetches. The PAR/token POST path
// (Dependencies.HTTP, a fully-trusted collaborator with no assertion
// of its own) previously had no equivalent.
func TestBeginAuthorizationRejectsStrippedTLS(t *testing.T) {
	cfg, ts := newTLSTestConfig(t)
	deps := validDependencies(t)
	deps.HTTP = strippedTLSHTTPClient{real: ts.Client()}

	c, err := client.New(cfg, deps)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	_, err = c.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{Scope: []string{"openid"}})
	if err == nil {
		t.Fatal("BeginAuthorization(stripped TLS) = nil error, want error")
	}
	if !errors.Is(err, fapihttp.ErrMissingTLS) {
		t.Fatalf("BeginAuthorization(stripped TLS) = %v, want fapihttp.ErrMissingTLS", err)
	}
}

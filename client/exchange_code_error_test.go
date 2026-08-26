package client_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
)

// TestExchangeCodeRejectsPlainTokenError confirms a token-endpoint error
// that isn't a use_dpop_nonce challenge surfaces directly, without
// attempting a retry — the non-retryable branch of ExchangeCode's own
// DPoP-nonce handling.
func TestExchangeCodeRejectsPlainTokenError(t *testing.T) {
	c, as, _ := newTestClient(t, false)
	as.rejectTokenRequestPlain = true
	ctx := context.Background()

	session, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid", "accounts"}})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	rawQuery := as.callbackFor(t, session.Handle().String(), "auth-code-123", "")
	if _, err := c.CompleteAuthorization(ctx, client.AuthorizationCallback{RawQuery: rawQuery}); err == nil {
		t.Fatal("CompleteAuthorization(plain token error) = nil error, want error")
	}
	if as.tokenCallCount != 1 {
		t.Fatalf("tokenCallCount = %d, want 1 (no retry for a non-DPoP-nonce error)", as.tokenCallCount)
	}
}

// TestExchangeCodeGivesUpAfterRetryStillFails confirms that when the
// authorization server keeps challenging for a DPoP nonce even after
// the retry carries one, ExchangeCode surfaces that second failure
// rather than retrying indefinitely.
func TestExchangeCodeGivesUpAfterRetryStillFails(t *testing.T) {
	c, as, _ := newTestClient(t, false)
	as.alwaysChallengeDPoPNonce = true
	ctx := context.Background()

	session, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid", "accounts"}})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	rawQuery := as.callbackFor(t, session.Handle().String(), "auth-code-123", "")
	if _, err := c.CompleteAuthorization(ctx, client.AuthorizationCallback{RawQuery: rawQuery}); err == nil {
		t.Fatal("CompleteAuthorization(persistent DPoP-nonce challenge) = nil error, want error")
	}
	if as.tokenCallCount != 2 {
		t.Fatalf("tokenCallCount = %d, want 2 (one attempt, one retry, then give up)", as.tokenCallCount)
	}
}

// failNthRequestHTTPClient wraps a real HTTP client and makes the nth
// request to a path ending in pathSuffix fail outright with a
// transport-level error, passing every other request through unchanged
// — simulating a network blip, as opposed to the server returning an
// HTTP error response (which the other tests in this file cover).
type failNthRequestHTTPClient struct {
	real       *http.Client
	pathSuffix string
	failOn     int
	seen       int
}

func (f *failNthRequestHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if strings.HasSuffix(req.URL.Path, f.pathSuffix) {
		f.seen++
		if f.seen == f.failOn {
			return nil, fmt.Errorf("simulated transport failure")
		}
	}
	return f.real.Do(req)
}

// newTestClientWithFailingTokenRequest is newTestClient (baseline
// profile), except the token endpoint's failOn-th request fails at the
// transport level rather than ever reaching the fake authorization
// server — exercising ExchangeCode's "the request itself failed"
// path, distinct from every other test in this package, which only
// ever exercises the server returning an HTTP-level error or success.
func newTestClientWithFailingTokenRequest(t *testing.T, failOn int) (*client.Client, *fakeAS) {
	t.Helper()
	as := newFakeAS(t, testIssuer, false)
	ts := httptest.NewServer(as.handler())
	t.Cleanup(ts.Close)

	cfg := validConfig(t)
	parURL, err := fapi.ParseEndpointURL(ts.URL+"/par", fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseEndpointURL(par): %v", err)
	}
	tokenURL, err := fapi.ParseEndpointURL(ts.URL+"/token", fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseEndpointURL(token): %v", err)
	}
	cfg.Endpoints.PushedAuthorizationRequest = parURL
	cfg.Endpoints.Token = tokenURL

	deps := validDependencies(t)
	deps.HTTP = &failNthRequestHTTPClient{real: ts.Client(), pathSuffix: "/token", failOn: failOn}
	deps.IssuerKeys = &fakeIssuerKeySource{}

	failing, err := client.New(cfg, deps)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	return failing, as
}

func TestExchangeCodePropagatesTransportErrorOnFirstAttempt(t *testing.T) {
	c, as := newTestClientWithFailingTokenRequest(t, 1)
	ctx := context.Background()

	session, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid", "accounts"}})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	rawQuery := as.callbackFor(t, session.Handle().String(), "auth-code-123", "")
	if _, err := c.CompleteAuthorization(ctx, client.AuthorizationCallback{RawQuery: rawQuery}); err == nil {
		t.Fatal("CompleteAuthorization(transport failure on first attempt) = nil error, want error")
	}
}

func TestExchangeCodePropagatesTransportErrorOnRetry(t *testing.T) {
	c, as := newTestClientWithFailingTokenRequest(t, 2)
	as.challengeDPoPNonce = "server-issued-nonce"
	ctx := context.Background()

	session, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid", "accounts"}})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	rawQuery := as.callbackFor(t, session.Handle().String(), "auth-code-123", "")
	if _, err := c.CompleteAuthorization(ctx, client.AuthorizationCallback{RawQuery: rawQuery}); err == nil {
		t.Fatal("CompleteAuthorization(transport failure on retry) = nil error, want error")
	}
}

package main

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// TestSmokeAuthorizeRefusesARepeatedParameter covers the authorization
// endpoint reading its request strictly: a repeated request_uri is
// refused locally as invalid_request, never redirected.
func TestSmokeAuthorizeRefusesARepeatedParameter(t *testing.T) {
	h := newSmokeHarness(t, AccessTokenFormatJWT)
	res, err := h.httpClient.Get(h.authorize + "?client_id=smoke-test-client&request_uri=urn%3Aa&request_uri=urn%3Ab")
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer func() { _ = res.Body.Close() }()
	body, _ := io.ReadAll(res.Body)
	// The repeat itself is refused, not the request_uri it names.
	if res.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), "invalid_request") || !strings.Contains(string(body), "the authorization request is malformed") {
		t.Fatalf("repeated request_uri = %d:\n%s\nwant a local 400 invalid_request for the malformed request", res.StatusCode, body)
	}
}

// TestSmokeAuthorizeRedirectsAnErrorToARegisteredRedirectURI covers the
// suite-only path: an unrecognised request_uri, with a redirect_uri the
// client registered, is answered by redirecting the error there.
func TestSmokeAuthorizeRedirectsAnErrorToARegisteredRedirectURI(t *testing.T) {
	h := newSmokeHarness(t, AccessTokenFormatJWT)
	q := url.Values{"client_id": {"smoke-test-client"}, "request_uri": {"urn:ietf:params:oauth:request_uri:unknown"},
		"redirect_uri": {"https://rp.smoketest.internal/callback"}, "state": {"s-1"}}
	res, err := h.httpClient.Get(h.authorize + "?" + q.Encode())
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer func() { _ = res.Body.Close() }()
	loc, _ := url.Parse(res.Header.Get("Location"))
	if res.StatusCode != http.StatusFound || loc == nil || loc.Host != "rp.smoketest.internal" || loc.Query().Get("state") != "s-1" || loc.Query().Get("error") == "" {
		t.Fatalf("unknown request_uri = %d, Location %q; want a redirect of the error, with state, to the registered URI", res.StatusCode, res.Header.Get("Location"))
	}
}

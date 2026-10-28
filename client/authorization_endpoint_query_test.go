package client_test

import (
	"context"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
)

// TestBeginAuthorizationRetainsTheEndpointsQuery: RFC 6749 §3.1 has the
// authorization endpoint URI's own query "retained when adding
// additional query parameters". It is kept byte for byte — order, a
// value-less name, a ";" and an escape url.ParseQuery can't decode — and
// client_id and request_uri follow it.
func TestBeginAuthorizationRetainsTheEndpointsQuery(t *testing.T) {
	const endpointURL = "https://as.example.com/authorize?tenant=acme&b=2&a=1&flag&x=1;y=2&bad=%zz"
	c, _, _ := newTestClientWith(t, false, func(cfg *client.Config, _ *client.Dependencies) {
		endpoint, err := fapi.ParseEndpointURL(endpointURL, fapi.AllowLoopbackHTTP())
		if err != nil {
			t.Fatalf("ParseEndpointURL: %v", err)
		}
		cfg.Endpoints.Authorization = endpoint
	})
	session, err := c.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{Scope: []string{"openid"}})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	got := session.URL().String()
	if !strings.HasPrefix(got, endpointURL+"&") {
		t.Fatalf("URL = %q, want the endpoint %q followed by the request's parameters", got, endpointURL)
	}
	added := got[len(endpointURL)+1:]
	if !strings.HasPrefix(added, "client_id=") || !strings.Contains(added, "&request_uri=") {
		t.Fatalf("added parameters = %q, want client_id and request_uri", added)
	}
}

// New refuses an authorization endpoint whose query names a parameter
// BeginAuthorization adds, and a redirect URI whose query names one an
// authorization response adds: retained and added to, either would be
// sent twice.
func TestNewRefusesQueriesNamingAddedParameters(t *testing.T) {
	for name, tc := range map[string]struct {
		endpoint, redirectURI string
	}{
		"endpoint client_id":   {endpoint: "https://as.example.com/authorize?client_id=stale"},
		"endpoint request_uri": {endpoint: "https://as.example.com/authorize?a=1;request_uri=x"},
		"redirect state":       {redirectURI: "https://rp.example.com/cb?state=registered"},
		"redirect iss":         {redirectURI: "https://rp.example.com/cb?i%73s=x"},
		"redirect code":        {redirectURI: "https://rp.example.com/cb?tenant=acme&code"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := validConfig(t)
			if tc.endpoint != "" {
				endpoint, err := fapi.ParseEndpointURL(tc.endpoint)
				if err != nil {
					t.Fatalf("ParseEndpointURL: %v", err)
				}
				cfg.Endpoints.Authorization = endpoint
			}
			if tc.redirectURI != "" {
				cfg.RedirectURI = tc.redirectURI
			}
			if _, err := client.New(cfg, validDependencies(t)); err == nil {
				t.Fatal("New = nil error, want an error naming the query parameter")
			}
		})
	}
}

func TestNewAcceptsQueriesNotNamingAddedParameters(t *testing.T) {
	cfg := validConfig(t)
	endpoint, err := fapi.ParseEndpointURL("https://as.example.com/authorize?tenant=acme&client=x")
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	cfg.Endpoints.Authorization = endpoint
	cfg.RedirectURI = "https://rp.example.com/cb?tenant=acme&states=1"
	if _, err := client.New(cfg, validDependencies(t)); err != nil {
		t.Fatalf("New: %v", err)
	}
}

package client_test

import (
	"context"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
)

// TestBeginAuthorizationRetainsTheEndpointsQuery: RFC 6749 §3.1 has the
// authorization endpoint URI's own query "retained when adding
// additional query parameters". client_id and request_uri replace any
// of the same name there, since a parameter may appear only once.
func TestBeginAuthorizationRetainsTheEndpointsQuery(t *testing.T) {
	c, _, _ := newTestClientWith(t, false, func(cfg *client.Config, _ *client.Dependencies) {
		endpoint, err := fapi.ParseEndpointURL("https://as.example.com/authorize?tenant=acme&client_id=stale", fapi.AllowLoopbackHTTP())
		if err != nil {
			t.Fatalf("ParseEndpointURL: %v", err)
		}
		cfg.Endpoints.Authorization = endpoint
	})
	session, err := c.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{Scope: []string{"openid"}})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	u := session.URL().URL()
	q := u.Query()
	if q.Get("tenant") != "acme" {
		t.Errorf("URL %q dropped the endpoint's own tenant parameter", u.String())
	}
	if got := q["client_id"]; len(got) != 1 || got[0] == "stale" {
		t.Errorf("client_id = %v, want this client's alone", got)
	}
	if q.Get("request_uri") == "" {
		t.Errorf("URL %q has no request_uri", u.String())
	}
}

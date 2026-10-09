package client_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/fapihttp"
)

// Discover reads an authorization server's OpenID Connect Discovery
// document. Here the server is a local test server, so the fetcher
// allows loopback hosts; against a real one, use fapihttp.NewClient's
// transport and leave every loopback option off.
func ExampleDiscover() {
	var issuer string
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                issuer,
			"authorization_endpoint":                issuer + "/authorize",
			"token_endpoint":                        issuer + "/token",
			"pushed_authorization_request_endpoint": issuer + "/par",
			"jwks_uri":                              issuer + "/jwks",
			"response_types_supported":              []string{"code"},
			"id_token_signing_alg_values_supported": []string{"ES256"},
		})
	}))
	defer ts.Close()
	issuer = ts.URL

	cfg := fapihttp.RecommendedConfig()
	cfg.AllowLoopbackHosts = true // the test server only
	fetcher, err := fapihttp.New(ts.Client(), cfg)
	if err != nil {
		fmt.Println(err)
		return
	}
	iss, err := fapi.ParseIssuerURL(issuer)
	if err != nil {
		fmt.Println(err)
		return
	}
	discovered, err := client.Discover(context.Background(), fetcher, iss)
	if err != nil {
		fmt.Println(err)
		return
	}
	for _, endpoint := range []fapi.URL{discovered.Endpoints.PushedAuthorizationRequest, discovered.Endpoints.Authorization, discovered.Endpoints.Token} {
		u, _ := url.Parse(endpoint.String())
		fmt.Println(u.Path)
	}
	// Output:
	// /par
	// /authorize
	// /token
}

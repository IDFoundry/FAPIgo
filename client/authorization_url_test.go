package client_test

import (
	"context"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/client"
)

// TestBeginAuthorizationURLCarriesOnlyClientIDAndRequestURI: FAPI 2.0
// Security Profile §5.3.3 has the client send every authorization
// parameter through PAR, so the URL the user agent is sent to names
// only client_id and request_uri (RFC 9126 §4), whatever the profile,
// callback binding, redirect port or request options.
func TestBeginAuthorizationURLCarriesOnlyClientIDAndRequestURI(t *testing.T) {
	everything := client.BeginAuthorizationRequest{
		Scope:              []string{"openid", "accounts"},
		ACRValues:          []string{"urn:example:silver"},
		MaxAge:             5 * time.Minute,
		HasMaxAge:          true,
		EssentialACRValues: []string{"urn:example:gold"},
		Claims:             client.RequestedClaims{IDToken: []string{"email"}, UserInfo: []string{"address"}},
	}
	for name, tc := range map[string]struct {
		messageSigned bool
		mutate        func(*client.Config, *client.Dependencies)
		req           client.BeginAuthorizationRequest
	}{
		"plain":                 {req: client.BeginAuthorizationRequest{Scope: []string{"openid"}}},
		"plain, every option":   {req: everything},
		"message signing (JAR)": {messageSigned: true, req: everything},
		"device-local callback binding": {
			mutate: func(cfg *client.Config, _ *client.Dependencies) {
				cfg.CallbackBinding = client.CallbackBindingDeviceLocalStore
			},
			req: everything,
		},
		"native loopback with a redirect port": {
			mutate: func(cfg *client.Config, _ *client.Dependencies) { cfg.RedirectURI = "http://127.0.0.1/callback" },
			req:    client.BeginAuthorizationRequest{Scope: []string{"openid"}, RedirectPort: 51004},
		},
	} {
		t.Run(name, func(t *testing.T) {
			c, _, _ := newTestClientWith(t, tc.messageSigned, tc.mutate)
			session, err := c.BeginAuthorization(context.Background(), tc.req)
			if err != nil {
				t.Fatalf("BeginAuthorization: %v", err)
			}
			u, err := url.Parse(session.URL().String())
			if err != nil {
				t.Fatalf("url.Parse(%q): %v", session.URL(), err)
			}
			if u.Fragment != "" {
				t.Errorf("URL %q has a fragment", u)
			}
			query := u.Query()
			names := make([]string, 0, len(query))
			for name, values := range query {
				names = append(names, name)
				if len(values) != 1 {
					t.Errorf("query parameter %q appears %d times, want once", name, len(values))
				}
			}
			slices.Sort(names)
			if !slices.Equal(names, []string{"client_id", "request_uri"}) {
				t.Errorf("query parameters = %v, want exactly [client_id request_uri]", names)
			}
			if got := query.Get("request_uri"); got != "urn:ietf:params:oauth:request_uri:abc123" {
				t.Errorf("request_uri = %q, want the one PAR returned", got)
			}
			if got := query.Get("client_id"); got != testClientID {
				t.Errorf("client_id = %q, want %q", got, testClientID)
			}
			if got := u.Scheme + "://" + u.Host + u.Path; got != testIssuer+"/authorize" {
				t.Errorf("URL = %q, want the authorization endpoint %q", got, testIssuer+"/authorize")
			}
		})
	}
}

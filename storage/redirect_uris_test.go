package storage

import (
	"slices"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
)

// TestRedirectURIsOptionalWithoutAuthorizationCode covers #452: only the
// authorization code grant redirects, so a client registered only for
// CIBA or client credentials needs no redirect URI — and can't use that
// grant — while a client with neither still does.
func TestRedirectURIsOptionalWithoutAuthorizationCode(t *testing.T) {
	base := RegisteredClientConfig{ID: "c", ClientAssertionAlgorithm: fapi.ES256, AllowedScopes: []string{"openid"}}
	for name, tc := range map[string]struct {
		mutate  func(*RegisteredClientConfig)
		wantErr bool
	}{
		"CIBA only":               {mutate: func(c *RegisteredClientConfig) { c.BackchannelAuthenticationRequestAlgorithm = fapi.ES256 }},
		"client credentials only": {mutate: func(c *RegisteredClientConfig) { c.AllowsClientCredentialsGrant = true }},
		"neither":                 {mutate: func(*RegisteredClientConfig) {}, wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := base
			tc.mutate(&cfg)
			c, err := NewRegisteredClient(cfg)
			if tc.wantErr {
				if err == nil {
					t.Fatal("NewRegisteredClient(no redirect URIs, no other grant) = nil error, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("NewRegisteredClient: %v", err)
			}
			if c.AllowsAuthorizationCodeGrant() {
				t.Error("AllowsAuthorizationCodeGrant() = true for a client with no redirect URI")
			}
		})
	}
	withRedirect := base
	withRedirect.RedirectURIs = []fapi.RegisteredRedirectURI{"https://rp.example/cb"}
	c, err := NewRegisteredClient(withRedirect)
	if err != nil || !c.AllowsAuthorizationCodeGrant() {
		t.Errorf("client with a redirect URI: AllowsAuthorizationCodeGrant() = %v, err %v", c.AllowsAuthorizationCodeGrant(), err)
	}
}

// TestRegisteredClientRedirectURIs: the registered redirect URIs come
// back in registration order, as a copy the caller can't use to change
// the registration.
func TestRegisteredClientRedirectURIs(t *testing.T) {
	want := []fapi.RegisteredRedirectURI{"https://rp.example/b", "https://rp.example/a"}
	c, err := NewRegisteredClient(RegisteredClientConfig{ID: "c", RedirectURIs: want, ClientAssertionAlgorithm: fapi.ES256, AllowedScopes: []string{"openid"}})
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}
	got := c.RedirectURIs()
	if !slices.Equal(got, want) {
		t.Fatalf("RedirectURIs() = %v, want %v", got, want)
	}
	got[0] = "https://attacker.example/cb"
	if c.HasRedirectURI("https://attacker.example/cb") || !slices.Equal(c.RedirectURIs(), want) {
		t.Fatal("changing RedirectURIs()'s result changed the registration")
	}
}

// RFC 6749 §3.1.2 has the server retain a redirect URI's query and add
// the response's parameters after it, so a registered query naming one
// of them would send it twice. NewRegisteredClient refuses such a URI,
// however the name is spelled or separated.
func TestNewRegisteredClientRefusesRedirectQueryNamingResponseParameter(t *testing.T) {
	for uri, wantErr := range map[string]bool{
		"https://rp.example/cb?state=registered":     true,
		"https://rp.example/cb?a=1&code=x":           true,
		"https://rp.example/cb?a=1;iss=x":            true,
		"https://rp.example/cb?st%61te=x":            true,
		"https://rp.example/cb?error":                true,
		"https://rp.example/cb?response=x":           true,
		"https://rp.example/cb?error_uri=x":          true,
		"https://rp.example/cb?error_description=x":  true,
		"https://rp.example/cb?tenant=acme&flag":     false,
		"https://rp.example/cb?State=x":              false,
		"https://rp.example/cb?codes=x&statement=1":  false,
		"https://rp.example/cb":                      false,
		"https://rp.example/cb?x=state&y=code%3Dabc": false,
	} {
		t.Run(uri, func(t *testing.T) {
			_, err := NewRegisteredClient(RegisteredClientConfig{
				ID: "c", RedirectURIs: []fapi.RegisteredRedirectURI{fapi.RegisteredRedirectURI(uri)},
				ClientAssertionAlgorithm: fapi.ES256, AllowedScopes: []string{"openid"},
			})
			if (err != nil) != wantErr {
				t.Fatalf("NewRegisteredClient(%q) error = %v, want error %v", uri, err, wantErr)
			}
		})
	}
}

// RFC 6749 §3.1.2: a redirect URI "MUST NOT include a fragment
// component", and "#" alone is one (RFC 3986 §3.5). NewRegisteredClient
// refuses it for a web or a native client, rather than registering a
// URI that matches only a request spelled with the same bare "#".
func TestNewRegisteredClientRefusesRedirectFragment(t *testing.T) {
	for _, tc := range []struct {
		uri    string
		native bool
	}{
		{"https://rp.example/cb#", false},
		{"https://rp.example/cb#frag", false},
		{"https://rp.example/cb?a=1#", false},
		{"http://127.0.0.1/cb#", true},
		{"com.example.app:/cb#", true},
	} {
		t.Run(tc.uri, func(t *testing.T) {
			cfg := RegisteredClientConfig{
				ID: "c", RedirectURIs: []fapi.RegisteredRedirectURI{fapi.RegisteredRedirectURI(tc.uri)},
				ClientAssertionAlgorithm: fapi.ES256, AllowedScopes: []string{"openid"},
			}
			if tc.native {
				cfg.ApplicationType = ApplicationTypeNative
			}
			if c, err := NewRegisteredClient(cfg); err == nil {
				t.Fatalf("NewRegisteredClient(%q) accepted it; HasRedirectURI = %v", tc.uri, c.HasRedirectURI(tc.uri))
			}
		})
	}
}

// A redirect goes to a redirect URI's normalized form, so
// NewRegisteredClient refuses, for a web or a native client, one not
// written that way: it would be matched as registered but sent
// somewhere spelled differently.
func TestNewRegisteredClientRefusesRedirectURINotWrittenAsSent(t *testing.T) {
	for _, tc := range []struct {
		uri    string
		native bool
		want   bool
	}{
		{"https://rp.example/c b", false, false},
		{"https://rp.example/café", false, false},
		{"https://RP.example/cb", false, false},
		{"HTTPS://rp.example/cb", false, false},
		{"http://127.0.0.1:8080/c b", false, false},
		{"com.example.app:/c b", true, false},
		{"Com.Example.App:/cb", true, false},
		{"https://rp.example/c%20b?x=a%20b", false, true},
		{"https://rp.example:8443/cb", false, true},
		{"com.example.app:/cb", true, true},
	} {
		t.Run(tc.uri, func(t *testing.T) {
			cfg := RegisteredClientConfig{
				ID: "c", RedirectURIs: []fapi.RegisteredRedirectURI{fapi.RegisteredRedirectURI(tc.uri)},
				ClientAssertionAlgorithm: fapi.ES256, AllowedScopes: []string{"openid"},
			}
			if tc.native {
				cfg.ApplicationType = ApplicationTypeNative
			}
			_, err := NewRegisteredClient(cfg)
			if (err == nil) != tc.want {
				t.Fatalf("NewRegisteredClient(%q) = %v, want accepted %v", tc.uri, err, tc.want)
			}
			if !tc.want && !strings.Contains(err.Error(), "written exactly as it is sent") {
				t.Errorf("NewRegisteredClient(%q) = %v, want it to say how to write the URI", tc.uri, err)
			}
		})
	}
}

// A redirect URI url.Parse refuses is left to where it's parsed as a
// redirect URI, a native client's at registration and a web client's at
// its pushed authorization request, rather than reported as one not
// written as it's sent.
func TestRedirectURINotWrittenAsSentSkipsUnparsable(t *testing.T) {
	cfg := RegisteredClientConfig{ID: "c", RedirectURIs: []fapi.RegisteredRedirectURI{"https://rp.example/%zz"}}
	if err := checkRedirectURIsWrittenAsSent(cfg); err != nil {
		t.Errorf("checkRedirectURIsWrittenAsSent(unparsable) = %v, want it left to the redirect URI parse", err)
	}
}

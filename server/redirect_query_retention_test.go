package server_test

import (
	"context"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// RFC 6749 §3.1.2: a redirect URI's query component "MUST be retained
// when adding additional query parameters". The response's parameters
// follow the registered query, which is kept byte for byte — not
// reordered, and with a value-less name, a ";" and an escape
// url.ParseQuery can't decode all left as registered.
func TestAuthorizationResponseRetainsRedirectQuery(t *testing.T) {
	for name, profile := range map[string]server.Profile{"plain": server.ProfileFAPISecurity, "message signing": server.ProfileFAPISecurityWithMessageSigning} {
		for _, registered := range []string{
			"https://rp.example/callback?b=2&a=1",
			"https://rp.example/callback?flag",
			"https://rp.example/callback?x=1;y=2",
			"https://rp.example/callback?bad=%zz&keep=1",
			"https://rp.example/callback?",
		} {
			t.Run(name+" "+registered, func(t *testing.T) {
				assertRedirectQueryRetained(t, profile, registered)
			})
		}
	}
}

func assertRedirectQueryRetained(t *testing.T, profile server.Profile, registered string) {
	t.Helper()
	h := newHarnessWithRedirectURI(t, profile, true, registered, server.AssuranceDevelopment)
	client, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID: testClientID, RedirectURIs: []fapi.RegisteredRedirectURI{fapi.RegisteredRedirectURI(registered)},
		ClientAssertionAlgorithm: fapi.ES256, AllowedScopes: []string{"openid"},
	})
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}
	dest, err := h.server.BuildAuthorizationErrorRedirect(context.Background(), client, registered, "xyz", "access_denied", "")
	if err != nil {
		t.Fatalf("BuildAuthorizationErrorRedirect: %v", err)
	}
	got := dest.String()
	prefix := registered
	if !strings.HasSuffix(prefix, "?") {
		prefix += "&"
	}
	if !strings.HasPrefix(got, prefix) {
		t.Fatalf("destination = %q, want the registered %q followed by the response's parameters", got, registered)
	}
	responseParams := got[len(prefix):]
	if profile == server.ProfileFAPISecurityWithMessageSigning {
		if !strings.HasPrefix(responseParams, "response=") || strings.Contains(responseParams, "&") {
			t.Fatalf("response parameters = %q, want the one JARM response", responseParams)
		}
		return
	}
	for _, want := range []string{"error=access_denied", "state=xyz", "iss="} {
		if !strings.Contains(responseParams, want) {
			t.Fatalf("response parameters = %q, missing %q", responseParams, want)
		}
	}
}

package storage

import (
	"testing"

	fapi "github.com/idfoundry/fapigo"
)

func nativeClient(t *testing.T, uris ...fapi.RegisteredRedirectURI) (RegisteredClient, error) {
	t.Helper()
	return NewRegisteredClient(RegisteredClientConfig{
		ID: "wallet", RedirectURIs: uris, ClientAssertionAlgorithm: fapi.ES256, ApplicationType: ApplicationTypeNative,
	})
}

func TestNativeRedirectURIsAtRegistration(t *testing.T) {
	for uri, want := range map[fapi.RegisteredRedirectURI]bool{
		"org.idfoundry.oid4vcgo.demowallet:/callback": true,
		"http://127.0.0.1/callback":                   true,
		"http://[::1]/callback":                       true,
		"http://127.0.0.1:8400/callback":              true,
		"https://wallet.example/callback":             true,
		"myapp:/callback":                             false, // RFC 8252 §8.4: no "."
		"http://localhost/callback":                   false, // §8.3: not a name
		"http://127.0.0.2/callback":                   false,
		"http://[::ffff:127.0.0.1]/callback":          false, // IPv4-mapped: not the literal
		"http://127.0.0.1:/callback":                  false, // an empty port: would never match
		"http://[::1]:/callback":                      false,
		"http://127.0.0.1:0/callback":                 false,
		"http://127.0.0.1:99999/callback":             false,
		"http://127.0.0.1:65535/callback":             true,
		"http://wallet.example/callback":              false,
		"com.example.app://host/callback":             false,
	} {
		if _, err := nativeClient(t, uri); (err == nil) != want {
			t.Errorf("native client with %q: %v, want accepted %v", uri, err, want)
		}
	}
	if _, err := NewRegisteredClient(RegisteredClientConfig{
		ID: "c", RedirectURIs: []fapi.RegisteredRedirectURI{"https://rp.example/cb"}, ClientAssertionAlgorithm: fapi.ES256, ApplicationType: 9,
	}); err == nil {
		t.Error("NewRegisteredClient accepted an unknown application type")
	}
}

// TestNativeLoopbackMatchesAnyPort covers RFC 8252 §7.3 and §8.4: a
// native client's loopback redirect URI matches on any port, and
// exactly otherwise; a web client's still matches exactly.
func TestNativeLoopbackMatchesAnyPort(t *testing.T) {
	native, err := nativeClient(t, "http://127.0.0.1/callback", "http://[::1]:8400/callback")
	if err != nil {
		t.Fatal(err)
	}
	for candidate, want := range map[string]bool{
		"http://127.0.0.1/callback":         true,
		"http://127.0.0.1:51004/callback":   true,
		"http://[::1]:61023/callback":       true,
		"http://[::1]/callback":             true,
		"http://127.0.0.1:51004/callback2":  false,
		"http://127.0.0.1:51004/callback?x": false,
		"http://127.0.0.1:0/callback":       false,
		"http://127.0.0.1:70000/callback":   false,
		"http://localhost:51004/callback":   false,
		"HTTP://127.0.0.1:51004/callback":   false,
		"http://u@127.0.0.1:51004/callback": false,
		"https://127.0.0.1:51004/callback":  false,
	} {
		if got := native.HasRedirectURI(candidate); got != want {
			t.Errorf("native HasRedirectURI(%q) = %v, want %v", candidate, got, want)
		}
	}
	web, err := NewRegisteredClient(RegisteredClientConfig{
		ID: "web", RedirectURIs: []fapi.RegisteredRedirectURI{"http://127.0.0.1/callback"}, ClientAssertionAlgorithm: fapi.ES256,
	})
	if err != nil {
		t.Fatal(err)
	}
	if web.HasRedirectURI("http://127.0.0.1:51004/callback") {
		t.Error("a web client's loopback redirect URI matched on another port")
	}
	if web.ApplicationType() != ApplicationTypeWeb || native.ApplicationType() != ApplicationTypeNative {
		t.Error("ApplicationType() doesn't report the registration")
	}
}

func TestApplicationTypeWireValues(t *testing.T) {
	for _, typ := range []ApplicationType{ApplicationTypeWeb, ApplicationTypeNative} {
		got, err := ParseApplicationType(typ.String())
		if err != nil || got != typ || !typ.IsValid() {
			t.Errorf("ParseApplicationType(%q) = %v, %v; want %v", typ.String(), got, err, typ)
		}
	}
	for _, s := range []string{"", "Native", "mobile"} {
		if _, err := ParseApplicationType(s); err == nil {
			t.Errorf("ParseApplicationType(%q) = nil error", s)
		}
	}
	if ApplicationType(9).IsValid() || ApplicationType(9).String() != "" {
		t.Error("an unknown ApplicationType is valid, or has a wire value")
	}
}

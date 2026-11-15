package fapi_test

import (
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
)

func TestParseRedirectURL(t *testing.T) {
	native := []fapi.URLOption{fapi.AllowLoopbackHTTP(), fapi.AllowPrivateUseScheme()}
	for raw, want := range map[string]bool{
		"https://rp.example/cb":                       true,
		"org.idfoundry.oid4vcgo.demowallet:/callback": true,
		"com.example.app:/cb?from=wallet":             true,
		"com.example-app.ios:/cb":                     true,
		"http://127.0.0.1:51004/cb":                   true,
		"myapp:/cb":                                   false, // not a reverse domain (RFC 8252 §8.4)
		"com.example.app:cb":                          false, // opaque, no path
		"com.example.app://host/cb":                   true,  // an authority
		"eu.europa.ec.euidi://authorization":          true,
		"com.example.app://host_1.a~b/cb?x=1":         true,
		"com.example.app:///cb":                       false, // an empty authority
		"com.example.app://":                          false,
		"com.example.app://host:443/cb":               false, // a port
		"com.example.app://user@host/cb":              false,
		"com.example.app://127.0.0.1/cb":              false, // an IP address
		"com.example.app://[::1]/cb":                  false,
		"com.example.app://ho%41st/cb":                false,
		"com.example.app://host/cb#frag":              false,
		"com.example.app://host/c b":                  false, // net/url would send "c%20b"
		"com.example.app:/c b":                        false,
		"com.example.app:/c%20b":                      true,
		"Com.Example.App:/cb":                         false, // sent with the scheme lowercased
		"https://rp.example/c b":                      false,
		"https://rp.example/caf\u00e9":                false, // sent as "caf%C3%A9"
		"https://rp.example/a|b":                      false,
		"https://RP.example/cb":                       false, // sent with the host lowercased
		"HTTPS://rp.example/cb":                       false,
		"http://127.0.0.1:51004/c b":                  false,
		"https://rp.example/a%7eb?x=a%20b&y=1;z":      true,
		"https://rp.example:8443/":                    true,
		"com.example.app://Wallet/cb":                 false, // an uppercase authority, sent lowercased
		"https://rp.example/cb?a=<x>":                 false, // a query RFC 3986 doesn't allow
		"https://rp.example/cb?a b":                   false,
		"https://rp.example/cb?a=%zz":                 false,
		"https://rp.example/cb?a=%2":                  false,
		"https://rp.example/cb?a=%2F&b=x:y@z/?":       true,
		"https://rp.example/a/../cb":                  false, // a dot segment, resolved away
		"https://rp.example/./cb":                     false,
		"https://rp.example/a/%2e%2E/cb":              false,
		"com.example.app:/a/../cb":                    false,
		"https://rp.example/a.b/..c/cb":               true,
		"https://rp.example:/cb":                      false, // an empty port
		"https://rp.example:0/cb":                     false,
		"https://rp.example:99999/cb":                 false,
		"http://[::1]:/cb":                            false,
		"https://rp.example":                          true,
		"https://rp.example/cb?":                      true,
		"com.example.app:////evil.example/cb":         false,
		"com..app:/cb":                                false,
		"com.-example.app:/cb":                        false,
		// RFC 3986 allows "+" and "." in a scheme, but RFC 8252 §7.1's
		// reverse domain name takes DNS labels: letters, digits and "-".
		"com.exa+mple.app:/cb":     false,
		"com.example.app:/cb#frag": false,
		"com.example.app:":         false,
		"http://rp.example/cb":     false,
		"":                         false,
	} {
		if _, err := fapi.ParseRedirectURL(raw, native...); (err == nil) != want {
			t.Errorf("ParseRedirectURL(%q, native) = %v, want accepted %v", raw, err, want)
		}
	}
	for _, raw := range []string{"com.example.app:/cb", "http://127.0.0.1:51004/cb"} {
		if _, err := fapi.ParseRedirectURL(raw); err == nil {
			t.Errorf("ParseRedirectURL(%q) without options = nil error, want https only", raw)
		}
	}
	if _, err := fapi.ParseEndpointURL("com.example.app:/cb", fapi.AllowPrivateUseScheme()); err == nil {
		t.Error("ParseEndpointURL accepted a private-use scheme: the option is for redirects only")
	}
	for _, raw := range []string{"org.idfoundry.oid4vcgo.demowallet:/callback", "eu.europa.ec.euidi://authorization", "com.example.app://host_1.a~b/cb?x=1"} {
		u, err := fapi.ParseRedirectURL(raw, native...)
		if err != nil || u.String() != raw {
			t.Errorf("ParseRedirectURL(%q) round trip = %q, %v", raw, u.String(), err)
		}
	}
}

// FuzzParseRedirectURL covers ParseRedirectURL on any input: it never
// panics, with no options accepts https alone, gives back any URI it
// accepts exactly as written, and accepts none that registration
// (CheckRedirectURIForm) would refuse.
func FuzzParseRedirectURL(f *testing.F) {
	for _, s := range []string{"https://rp.example/cb", "com.example.app:/cb", "http://[::1]:1/cb", "a.b:/", "a.b://x", "a.b://x/cb?y=1", "a.b:///x", "a.b://127.0.0.1/", "A.0:/ ", "https://RP.example/c b", "https://rp.example/cb?a=%zz", "a.b://W/cb", "https://rp.example/a/../b", "https://rp.example:/cb"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if u, err := fapi.ParseRedirectURL(raw, fapi.AllowLoopbackHTTP(), fapi.AllowPrivateUseScheme()); err == nil {
			if u.String() != raw {
				t.Fatalf("ParseRedirectURL(%q) = %q, not as written", raw, u.String())
			}
			// What the server accepts at a request, registration accepts.
			if err := fapi.CheckRedirectURIForm(raw); err != nil {
				t.Fatalf("ParseRedirectURL(%q) accepted it, CheckRedirectURIForm refused it: %v", raw, err)
			}
		}
		if u, err := fapi.ParseRedirectURL(raw); err == nil {
			if v := u.URL(); v.Scheme != "https" {
				t.Fatalf("ParseRedirectURL(%q) accepted scheme %q with no options", raw, v.Scheme)
			}
		}
	})
}

// TestParseRedirectURLSaysWhatToChange covers the refusals an
// integrator meets: an authority with a port, a private-use URI passed
// without the option, and a URI not written as it's sent.
func TestParseRedirectURLSaysWhatToChange(t *testing.T) {
	_, err := fapi.ParseRedirectURL("com.example.app://callback:8080", fapi.AllowPrivateUseScheme())
	if err == nil || !strings.Contains(err.Error(), "com.example.app:/path") {
		t.Errorf("ParseRedirectURL(authority with a port) = %v, want it to show the single-slash form", err)
	}
	_, err = fapi.ParseRedirectURL("com.example.app:/callback")
	if err == nil || strings.Contains(err.Error(), "must be absolute") {
		t.Errorf("ParseRedirectURL(no host, no option) = %v, want it to say the host is missing, not that it isn't absolute", err)
	}
	_, err = fapi.ParseRedirectURL("https://RP.example/c b")
	if err == nil || !strings.Contains(err.Error(), `"https://rp.example/c%20b"`) {
		t.Errorf("ParseRedirectURL(rewritten URI) = %v, want it to show the form it would be sent as", err)
	}
}

// TestCheckRedirectURIForm covers registration's check: the form rules
// ParseRedirectURL applies, whatever the scheme, and a URL that doesn't
// parse left to ParseRedirectURL.
func TestCheckRedirectURIForm(t *testing.T) {
	for raw, want := range map[string]bool{
		"https://rp.example/cb?a=1":   true,
		"http://rp.example/cb":        true, // a scheme a client may not use is the server's to refuse
		"myapp:/cb":                   true,
		"https://rp.example/%zz":      true, // doesn't parse: left to ParseRedirectURL
		"https://RP.example/cb":       false,
		"com.example.app://Wallet/cb": false,
		"https://rp.example/cb?a=<x>": false,
		"https://rp.example/a/../cb":  false,
		"https://rp.example:0/cb":     false,
		"https://rp.example:/cb":      false,
	} {
		if err := fapi.CheckRedirectURIForm(raw); (err == nil) != want {
			t.Errorf("CheckRedirectURIForm(%q) = %v, want accepted %v", raw, err, want)
		}
	}
}

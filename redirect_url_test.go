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
		"com.example.app://Host_1.a~b/cb?x=1":         true,
		"com.example.app:///cb":                       false, // an empty authority
		"com.example.app://":                          false,
		"com.example.app://host:443/cb":               false, // a port
		"com.example.app://user@host/cb":              false,
		"com.example.app://127.0.0.1/cb":              false, // an IP address
		"com.example.app://[::1]/cb":                  false,
		"com.example.app://ho%41st/cb":                false,
		"com.example.app://host/cb#frag":              false,
		"com.example.app://host/c b":                  false, // net/url would send "c%20b"
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
	for _, raw := range []string{"org.idfoundry.oid4vcgo.demowallet:/callback", "eu.europa.ec.euidi://authorization", "com.example.app://Host_1.a~b/cb?x=1"} {
		u, err := fapi.ParseRedirectURL(raw, native...)
		if err != nil || u.String() != raw {
			t.Errorf("ParseRedirectURL(%q) round trip = %q, %v", raw, u.String(), err)
		}
	}
}

// FuzzParseRedirectURL covers ParseRedirectURL on any input: it never
// panics, with no options accepts https alone, and gives back a
// private-use URI with an authority as written but for the scheme's
// case.
func FuzzParseRedirectURL(f *testing.F) {
	for _, s := range []string{"https://rp.example/cb", "com.example.app:/cb", "http://[::1]:1/cb", "a.b:/", "a.b://x", "a.b://x/cb?y=1", "a.b:///x", "a.b://127.0.0.1/"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if u, err := fapi.ParseRedirectURL(raw, fapi.AllowLoopbackHTTP(), fapi.AllowPrivateUseScheme()); err == nil {
			if v := u.URL(); v.Scheme != "http" && v.Scheme != "https" && v.Host != "" && u.String()[len(v.Scheme):] != raw[len(v.Scheme):] {
				t.Fatalf("ParseRedirectURL(%q) = %q, not as written", raw, u.String())
			}
		}
		if u, err := fapi.ParseRedirectURL(raw); err == nil {
			if v := u.URL(); v.Scheme != "https" {
				t.Fatalf("ParseRedirectURL(%q) accepted scheme %q with no options", raw, v.Scheme)
			}
		}
	})
}

// TestParseRedirectURLSaysWhatToChange covers the two refusals an
// integrator meets: an authority with a port, and a private-use URI
// passed without the option.
func TestParseRedirectURLSaysWhatToChange(t *testing.T) {
	_, err := fapi.ParseRedirectURL("com.example.app://callback:8080", fapi.AllowPrivateUseScheme())
	if err == nil || !strings.Contains(err.Error(), "com.example.app:/path") {
		t.Errorf("ParseRedirectURL(authority with a port) = %v, want it to show the single-slash form", err)
	}
	_, err = fapi.ParseRedirectURL("com.example.app:/callback")
	if err == nil || strings.Contains(err.Error(), "must be absolute") {
		t.Errorf("ParseRedirectURL(no host, no option) = %v, want it to say the host is missing, not that it isn't absolute", err)
	}
}

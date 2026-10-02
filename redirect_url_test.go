package fapi_test

import (
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
		"com.example.app://host/cb":                   false, // an authority
		"com..app:/cb":                                false,
		"com.-example.app:/cb":                        false,
		"com.example.app:/cb#frag":                    false,
		"com.example.app:":                            false,
		"http://rp.example/cb":                        false,
		"":                                            false,
	} {
		_, err := fapi.ParseRedirectURL(raw, native...)
		if got := err == nil; got != want {
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
	u, err := fapi.ParseRedirectURL("org.idfoundry.oid4vcgo.demowallet:/callback", native...)
	if err != nil || u.String() != "org.idfoundry.oid4vcgo.demowallet:/callback" {
		t.Errorf("ParseRedirectURL round trip = %q, %v", u.String(), err)
	}
}

// FuzzParseRedirectURL covers ParseRedirectURL on any input: it never
// panics, and with no options accepts https alone.
func FuzzParseRedirectURL(f *testing.F) {
	for _, s := range []string{"https://rp.example/cb", "com.example.app:/cb", "http://[::1]:1/cb", "a.b:/", "a.b://x"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		_, _ = fapi.ParseRedirectURL(raw, fapi.AllowLoopbackHTTP(), fapi.AllowPrivateUseScheme())
		if u, err := fapi.ParseRedirectURL(raw); err == nil {
			if v := u.URL(); v.Scheme != "https" {
				t.Fatalf("ParseRedirectURL(%q) accepted scheme %q with no options", raw, v.Scheme)
			}
		}
	})
}

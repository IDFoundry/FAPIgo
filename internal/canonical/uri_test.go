package canonical

import (
	"net/url"
	"testing"
)

func TestURI(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"strips query and fragment", "https://as.example/token?foo=bar#frag", "https://as.example/token"},
		{"lowercases scheme and host", "HTTPS://AS.Example/token", "https://as.example/token"},
		{"drops default https port", "https://as.example:443/token", "https://as.example/token"},
		{"drops default http port", "http://as.example:80/token", "http://as.example/token"},
		{"keeps non-default port", "https://as.example:8443/token", "https://as.example:8443/token"},
		{"strips userinfo", "https://user:pass@as.example/token", "https://as.example/token"},
		{"preserves path exactly", "https://as.example/a/b/../c", "https://as.example/a/b/../c"},
		{"drops default port on an IPv6 host", "https://[::1]:443/token", "https://[::1]/token"},
		{"keeps non-default port on an IPv6 host", "https://[::1]:8443/token", "https://[::1]:8443/token"},
		// The two cases below were found by FuzzURI, not written by
		// hand — see URI's own doc comment for why a leading "./" is
		// inserted. Once Scheme, Host and User have all come out empty,
		// a Path of "//..." is ambiguous when serialized (RFC 3986
		// §3.3) and would silently reparse into a different URL; both
		// example inputs below can only reach that state via a
		// component URI is supposed to strip (a degenerate host, or
		// userinfo), so this is a defense-in-depth guard against an
		// already-malformed htu claim, not a real absolute URL ever
		// taking this path.
		{"disambiguates a collapsed host colliding with a // path", "//://", ".///"},
		{"disambiguates stripped userinfo colliding with a // path", "//@//", ".///"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u, err := url.Parse(c.in)
			if err != nil {
				t.Fatalf("url.Parse(%q): %v", c.in, err)
			}
			got := URI(u)
			if got != c.want {
				t.Fatalf("URI(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

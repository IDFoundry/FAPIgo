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

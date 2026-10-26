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
		// RFC 3986 §6.2.2 and §6.2.3, as RFC 9449 §4.3 asks of htu.
		{"removes dot segments", "https://as.example/a/b/../c/./d", "https://as.example/a/c/d"},
		{"removes dot segments above the root", "https://as.example/../../a", "https://as.example/a"},
		{"decodes percent-encoded unreserved characters", "https://as.example/%7Euser/%61%2D%5F%2E", "https://as.example/~user/a-_."},
		{"uppercases other percent-encodings", "https://as.example/a%2fb%c3%a9", "https://as.example/a%2Fb%C3%A9"},
		{"keeps an encoded slash encoded", "https://as.example/a%2F..%2Fb", "https://as.example/a%2F..%2Fb"},
		{"removes percent-encoded dot segments", "https://as.example/a/%2E%2E/b", "https://as.example/b"},
		{"makes an empty path /", "https://as.example", "https://as.example/"},
		{"keeps a trailing slash", "https://as.example/a/", "https://as.example/a/"},
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

func TestRemoveDotSegments(t *testing.T) {
	for in, want := range map[string]string{
		// RFC 3986 §5.2.4's own examples.
		"/a/b/c/./../../g":   "/a/g",
		"mid/content=5/../6": "mid/6",
		// Each step of the algorithm.
		"../a":   "a",
		"./a":    "a",
		"/./a":   "/a",
		"/a/.":   "/a/",
		"/a/../": "/",
		"/a/..":  "/",
		"/..":    "/",
		".":      "",
		"..":     "",
		"/a/b":   "/a/b",
		"":       "",
	} {
		if got := removeDotSegments(in); got != want {
			t.Errorf("removeDotSegments(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestHasNormalPath: a path URI would change (other than in the case of
// a percent-encoding's hex digits) isn't normal, since a request sent
// with it addresses a different path than its DPoP proof's htu names.
func TestHasNormalPath(t *testing.T) {
	for raw, want := range map[string]bool{
		"https://rs.example/rs-b/payments":      true,
		"https://rs.example":                    true,
		"https://rs.example/":                   true,
		"https://rs.example/a/":                 true,
		"https://rs.example/a?x=../b&y=%2e":     true,
		"https://rs.example/a%2Fb":              true,
		"https://rs.example/a%2fb":              true,
		"https://rs.example/caf%C3%A9":          true,
		"https://rs.example/a/...":              true,
		"https://rs.example/.well-known/x":      true,
		"https://rs.example//double":            true,
		"https://rs.example/rs-a/%2e%2e/rs-b/x": false,
		"https://rs.example/rs-a/%2E%2E/rs-b/x": false,
		"https://rs.example/rs-a/../rs-b/x":     false,
		"https://rs.example/rs-a/./x":           false,
		"https://rs.example/rs-a/..":            false,
		"https://rs.example/%7Euser":            false,
		"https://rs.example/%61":                false,
		"https://rs.example/a/%2e":              false,
	} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("url.Parse(%q): %v", raw, err)
		}
		if got := HasNormalPath(u); got != want {
			t.Errorf("HasNormalPath(%q) = %v, want %v", raw, got, want)
		}
	}
	if HasNormalPath(&url.URL{Scheme: "https", Opaque: "//rs.example/a/../b"}) {
		t.Error("HasNormalPath(opaque URL) = true, want false")
	}
}

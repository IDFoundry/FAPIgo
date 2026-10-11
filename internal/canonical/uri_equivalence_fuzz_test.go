package canonical

import (
	"net"
	"net/url"
	"strings"
	"testing"
)

// effective returns what a URL actually addresses for DPoP htu purposes
// (RFC 9449 §4.3): scheme, host (lowercased, unbracketed), effective
// port and escaped path. Query, fragment and userinfo don't count.
func effective(u *url.URL) (scheme, host, port, path string) {
	scheme = strings.ToLower(u.Scheme)
	host = strings.ToLower(u.Hostname())
	port = u.Port()
	if port == "" {
		switch scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		}
	}
	return scheme, host, port, u.EscapedPath()
}

// FuzzURIEquivalence: two absolute http(s) URLs that canonicalize to
// the same string address the same scheme, host, port and path. A pair
// that canonicalizes equal while addressing different targets would let
// a DPoP proof made for one be accepted at the other.
func FuzzURIEquivalence(f *testing.F) {
	for _, p := range [][2]string{
		{"https://as.example/token", "https://AS.example:443/token"},
		{"https://as.example./token", "https://as.example/token"},
		{"https://as%2Eexample/token", "https://as.example/token"},
		{"https://[::1]/t", "https://[0:0::1]/t"},
		{"https://a.example/t", "https://user@a.example/t?q#f"},
		{"https://a.example/%2E%2E/t", "https://a.example/../t"},
	} {
		f.Add(p[0], p[1])
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		ua, okA := parseHTTPURL(a)
		ub, okB := parseHTTPURL(b)
		if !okA || !okB || URI(ua) != URI(ub) {
			return
		}
		as, ah, ap, apath := effective(ua)
		bs, bh, bp, bpath := effective(ub)
		if sameIPLiteral(ah, bh) {
			ah, bh = "", ""
		}
		if as != bs || ah != bh || ap != bp || apath != bpath {
			t.Fatalf("URI(%q) == URI(%q) == %q, but they address %q %q %q %q vs %q %q %q %q",
				a, b, URI(ua), as, ah, ap, apath, bs, bh, bp, bpath)
		}
	})
}

// parseHTTPURL parses raw as an absolute http(s) URL with a host.
func parseHTTPURL(raw string) (*url.URL, bool) {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, false
	}
	return u, true
}

// sameIPLiteral reports whether a and b are both IP literals with the
// same value, so IP hosts compare by value rather than spelling.
func sameIPLiteral(a, b string) bool {
	ia, ib := net.ParseIP(a), net.ParseIP(b)
	return ia != nil && ib != nil && ia.Equal(ib)
}

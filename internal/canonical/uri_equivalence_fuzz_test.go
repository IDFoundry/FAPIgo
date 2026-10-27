package canonical

import (
	"net"
	"net/url"
	"strings"
	"testing"
)

// effective returns what a URL actually addresses for DPoP htu purposes
// (RFC 9449 §4.3): scheme, host (ASCII-lowercased, unbracketed),
// effective port and escaped path. Query, fragment and userinfo don't
// count.
func effective(u *url.URL) (scheme, host, port, path string) {
	scheme = referenceLower(u.Scheme)
	host = referenceLower(u.Hostname())
	port = u.Port()
	if port == "" {
		switch scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		}
	}
	return scheme, host, port, referencePath(u.EscapedPath())
}

// referenceLower lowercases s's ASCII letters only, byte by byte, as
// host names and schemes are compared (RFC 3986 §3.1, §3.2.2). It is
// deliberately not strings.ToLower, whose Unicode case mapping folds
// "İ" (U+0130) to "i" and the Kelvin sign (U+212A) to "k": a non-ASCII
// host is dialed through IDNA as another DNS name altogether, so an
// oracle sharing that fold could never catch URI equating the two.
func referenceLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c | 0x20
		}
	}
	return string(b)
}

// referencePath is an independent reading of which path an escaped path
// addresses, coarser than RFC 3986 §6.2.2 so it never tells apart two
// paths URI equates: split on "/" before decoding, so an encoded "/"
// stays inside its segment; decode each segment whole; resolve "." and
// ".." segments; make an empty path "/" (§6.2.3).
func referencePath(escaped string) string {
	var segments []string
	parts := strings.Split(escaped, "/")
	for i, part := range parts {
		decoded, err := url.PathUnescape(part)
		if err != nil {
			decoded = part
		}
		last := i == len(parts)-1
		switch decoded {
		case ".":
			if last {
				segments = append(segments, "")
			}
		case "..":
			if len(segments) > 1 {
				segments = segments[:len(segments)-1]
			}
			if last {
				segments = append(segments, "")
			}
		default:
			segments = append(segments, decoded)
		}
	}
	joined := strings.Join(segments, "\x00")
	if joined == "" || joined == "\x00" {
		return "/"
	}
	return joined
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
		{"https://\u0130bank.example/t", "https://ibank.example/t"},
		{"https://\u212Aey.example/t", "https://key.example/t"},
		{"https://ba\u017Fe.example/t", "https://base.example/t"},
		{"https://\uFF22ank.example/t", "https://\uFF42ank.example/t"},
		{"https://%C4%B0bank.example/t", "https://ibank.example/t"},
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

package canonical

import (
	"net"
	"net/url"
	"strings"
)

// URI canonicalizes u for use as a DPoP "htu" claim (RFC 9449 §4.2) or
// any other context that needs to compare URLs by origin-plus-path:
// scheme and host are lowercased, a default port for the scheme is
// dropped, and any userinfo, query and fragment are stripped. The path
// is left exactly as supplied — this function does not perform
// path-segment normalization (".", "..", percent-decoding), since that
// would change which resource the URL identifies.
func URI(u *url.URL) string {
	out := *u
	out.Scheme = strings.ToLower(out.Scheme)
	out.Host = canonicalHost(out.Host, out.Scheme)
	out.User = nil
	out.RawQuery = ""
	out.Fragment = ""
	out.RawFragment = ""
	// A path starting with "//", once Scheme, Host and User have all
	// come out empty, is genuinely ambiguous once serialized: RFC 3986
	// §3.3 always reads a leading "//" as introducing an authority
	// component, so url.URL.String() (which only writes "//" itself
	// ahead of a non-empty Scheme/Host/User — none of which apply here)
	// just emits the path verbatim, and re-parsing that string reads
	// part or all of it back as a phantom Host instead of Path —
	// silently producing a *different* URL than the one just
	// canonicalized (confirmed by this package's own fuzz corpus: three
	// distinct shapes of "//"-prefixed path, each swallowed differently
	// on re-parse depending on what follows). This can only arise when
	// u's own original Host or User was non-empty to begin with — that
	// is the only way Path could have ended up starting with "//" in
	// the first place — so it is inherent to inputs already this
	// degenerate (no scheme, no real host), never to a well-formed
	// absolute URL. RFC 3986 §4.2 prescribes exactly this fix for the
	// analogous "first path segment could be mistaken for something
	// else" case (a leading "./"); Go's own url.URL.String() already
	// applies it for a first segment containing ":" — this extends the
	// same technique to "//", which net/url does not yet guard against
	// itself.
	if out.Scheme == "" && out.Host == "" && out.User == nil && strings.HasPrefix(out.Path, "//") {
		out.Path = "./" + out.Path
		if out.RawPath != "" {
			out.RawPath = "./" + out.RawPath
		}
	}
	return out.String()
}

func canonicalHost(host, scheme string) string {
	h, port, err := net.SplitHostPort(host)
	// A successful split strips an IPv6 literal's own brackets (e.g.
	// "[::1]:443" -> h="::1") — an error means h is host unchanged
	// below, so any brackets it originally had (e.g. bare "[::1]", no
	// port at all) are still there and must not be added again.
	splitStrippedBrackets := err == nil
	if err != nil {
		h = host
		port = ""
	}
	h = strings.ToLower(h)
	if port == "" || isDefaultPort(scheme, port) {
		// Without re-adding what a successful split stripped, a bare
		// return of h here would hand back an address containing
		// colons with nothing to mark it as a single host component —
		// net.JoinHostPort below re-adds them itself, but this branch
		// doesn't go through it. url.URL.String() would then serialize
		// h after "//" indistinguishably from a host:port pair, and
		// re-parsing that string fails outright (confirmed by this
		// package's own fuzz corpus).
		if splitStrippedBrackets && strings.Contains(h, ":") {
			return "[" + h + "]"
		}
		return h
	}
	return net.JoinHostPort(h, port)
}

func isDefaultPort(scheme, port string) bool {
	switch scheme {
	case "https":
		return port == "443"
	case "http":
		return port == "80"
	default:
		return false
	}
}

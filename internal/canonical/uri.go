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
	return out.String()
}

func canonicalHost(host, scheme string) string {
	h, port, err := net.SplitHostPort(host)
	if err != nil {
		h = host
		port = ""
	}
	h = strings.ToLower(h)
	if port == "" || isDefaultPort(scheme, port) {
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

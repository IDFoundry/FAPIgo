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
// gets RFC 3986's syntax-based and scheme-based normalization (§6.2.2,
// §6.2.3), which RFC 9449 §4.3 has a server apply before comparing htu:
// percent-encodings are uppercased, those of unreserved characters
// decoded, "." and ".." segments removed, and an http(s) URI's empty
// path made "/". Each keeps the resource the URI identifies, so two
// URIs that differ only in them name the same one.
func URI(u *url.URL) string {
	out := *u
	out.Scheme = strings.ToLower(out.Scheme)
	out.Host = canonicalHost(out.Host, out.Scheme)
	out.User = nil
	out.RawQuery = ""
	out.Fragment = ""
	out.RawFragment = ""
	path := normalizePath(u.EscapedPath())
	if path == "" && out.Host != "" && (out.Scheme == "https" || out.Scheme == "http") {
		path = "/" // RFC 3986 §6.2.3
	}
	if path == "%2A" {
		// net/url writes a Path of exactly "*" unescaped whatever its
		// RawPath, so this is the one form String can't keep.
		path = "*"
	}
	// path's percent-encodings are all valid: normalizePath only keeps
	// those of EscapedPath, which are.
	out.Path, _ = url.PathUnescape(path)
	out.RawPath = path
	// A path starting with "//", once Host and User have both come out
	// empty, is genuinely ambiguous once serialized: RFC 3986 §3.3
	// always reads a leading "//" as introducing an authority
	// component. With no scheme, url.URL.String() emits the path
	// verbatim; with a scheme and an input that had no authority
	// ("A:/.//", OmitHost set), it writes "scheme:" and then the path
	// (Go releases before 1.27 do; later ones escape its first "/").
	// Either way, re-parsing reads part or all of the path back as a
	// phantom Host — silently producing a *different* URL than the one
	// just canonicalized (confirmed by this package's own fuzz corpus:
	// "//://", "//@//" and "A:/.//" are each swallowed differently).
	// The path can only start with "//" here after dot-segment removal
	// ("/.//x") or because u's own Host or User was non-empty to begin
	// with, so this only arises for inputs already this degenerate (no
	// real host), never for a well-formed absolute URL. Prefixing "/."
	// keeps the path's meaning (RFC 3986 §5.2.4 removes it again) while
	// making the first segment "." rather than empty — the technique
	// §4.2 prescribes, with "./", for a first segment that could be
	// mistaken for a scheme. URI of the result removes the prefix and
	// adds it back, so it is idempotent.
	if out.Host == "" && out.User == nil && strings.HasPrefix(out.Path, "//") {
		out.Path = "/." + out.Path
		if out.RawPath != "" {
			out.RawPath = "/." + out.RawPath
		}
	}
	return out.String()
}

// HasNormalPath reports whether the request-target net/http sends for u
// names the same path URI puts in an htu: u is not opaque, and its
// escaped path has no "." or ".." segments and no percent-encoded
// unreserved characters, which URI's normalization would change. (A
// lowercase percent-encoding counts as normal: URI only uppercases it,
// and it names the same octet to anything that decodes the path.) A
// proof whose htu names another path than the request's own could be
// routed, by a front end that doesn't normalize, to a resource server
// other than the one its htu names, and replayed there.
func HasNormalPath(u *url.URL) bool {
	if u.Opaque != "" {
		return false
	}
	escaped := u.EscapedPath()
	return normalizePath(escaped) == upperPercentEncodings(escaped)
}

// upperPercentEncodings uppercases the hex digits of each well-formed
// percent-encoding in escaped, leaving everything else as it is.
func upperPercentEncodings(escaped string) string {
	b := []byte(escaped)
	for i := 0; i+2 < len(b); i++ {
		if b[i] == '%' && isHex(b[i+1]) && isHex(b[i+2]) {
			b[i+1], b[i+2] = upperHex(b[i+1]), upperHex(b[i+2])
			i += 2
		}
	}
	return string(b)
}

func upperHex(c byte) byte {
	if 'a' <= c && c <= 'f' {
		return c - 'a' + 'A'
	}
	return c
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

// normalizePath applies RFC 3986 §6.2.2's syntax-based normalization to
// an escaped path: percent-encodings uppercased (§6.2.2.1), those of
// unreserved characters decoded (§6.2.2.2), then dot segments removed
// (§6.2.2.3, by §5.2.4's algorithm). A "%" not followed by two hex
// digits is kept as it is.
func normalizePath(escaped string) string {
	var b strings.Builder
	b.Grow(len(escaped))
	for i := 0; i < len(escaped); i++ {
		c := escaped[i]
		if c != '%' || i+2 >= len(escaped) || !isHex(escaped[i+1]) || !isHex(escaped[i+2]) {
			b.WriteByte(c)
			continue
		}
		decoded := unhex(escaped[i+1])<<4 | unhex(escaped[i+2])
		if isUnreserved(decoded) {
			b.WriteByte(decoded)
		} else {
			b.WriteByte('%')
			b.WriteString(strings.ToUpper(escaped[i+1 : i+3]))
		}
		i += 2
	}
	return removeDotSegments(b.String())
}

// removeDotSegments is RFC 3986 §5.2.4's algorithm.
func removeDotSegments(in string) string {
	var out []string // output segments, each with its leading "/" if any
	for in != "" {
		switch {
		case strings.HasPrefix(in, "../"):
			in = in[3:]
		case strings.HasPrefix(in, "./"):
			in = in[2:]
		case strings.HasPrefix(in, "/./"):
			in = in[2:]
		case in == "/.":
			in = "/"
		case strings.HasPrefix(in, "/../"):
			in = in[3:]
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		case in == "/..":
			in = "/"
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		case in == "." || in == "..":
			in = ""
		default:
			// Move the first segment, with its leading "/" if any, up
			// to the next "/".
			end := strings.IndexByte(in[1:], '/') + 1
			if end == 0 {
				end = len(in)
			}
			out = append(out, in[:end])
			in = in[end:]
		}
	}
	return strings.Join(out, "")
}

func isUnreserved(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' ||
		c == '-' || c == '.' || c == '_' || c == '~'
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	}
	return c - 'A' + 10
}

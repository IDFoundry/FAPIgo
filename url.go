package fapi

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/idfoundry/fapigo/internal/canonical"
	"github.com/idfoundry/fapigo/internal/querystring"
)

// URL is a validated, security-sensitive URL — an issuer identifier, an
// endpoint or a redirect destination. It can only be constructed via
// ParseIssuerURL, ParseEndpointURL or ParseRedirectURL, which enforce:
// absolute, HTTPS (except an explicitly enabled loopback exception, or a
// native app's private-use scheme for a redirect), no embedded
// credentials, no fragment (not even an empty "#"), a host in ASCII (an internationalized
// domain name given as its xn-- A-label), and a normalized scheme and
// host (their ASCII letters lowercased).
type URL struct {
	value url.URL
}

type urlOptions struct {
	allowLoopbackHTTP     bool
	allowPrivateUseScheme bool
}

// URLOption configures ParseIssuerURL, ParseEndpointURL or
// ParseRedirectURL. AllowPrivateUseScheme applies to ParseRedirectURL
// only; the other two ignore it, and still refuse a URI with no host.
type URLOption func(*urlOptions)

// AllowLoopbackHTTP permits an http:// scheme when the host is a
// loopback address ("localhost", 127.0.0.0/8, or ::1). For an issuer or
// endpoint it exists for local development only and must never be
// enabled from configuration that could reach a production deployment
// by accident. For a native app's redirect URI (RFC 8252 §7.3) it is
// what FAPI 2.0 allows in production too.
func AllowLoopbackHTTP() URLOption {
	return func(o *urlOptions) { o.allowLoopbackHTTP = true }
}

// AllowPrivateUseScheme permits, for ParseRedirectURL only, a native
// app's private-use URI scheme redirect (RFC 8252 §7.1): a scheme that
// is a domain name in reverse order, so it contains a ".", then either a
// single slash and the path, "com.example.app:/oauth2redirect", the form
// RFC 8252 §7.1 writes and prefers, or an authority,
// "com.example.app://oauth2redirect", which some deployed wallets
// register. The authority, which the operating system ignores when it
// dispatches the redirect to the app, must be a name of ASCII letters,
// digits, "-", ".", "_" and "~", the letters lowercase, as a host is
// written: no userinfo, port or IP address. The
// scheme alone identifies the app, so show it, not the authority, where
// a user is told where they'll be sent. Either form is matched against
// the registered string exactly. Enable it only for a client registered
// as a native app.
func AllowPrivateUseScheme() URLOption {
	return func(o *urlOptions) { o.allowPrivateUseScheme = true }
}

// ParseRedirectURL parses and validates raw as an OAuth redirect URI:
// https, like ParseEndpointURL, unless an option admits loopback http
// (AllowLoopbackHTTP) or a native app's private-use scheme
// (AllowPrivateUseScheme). Unlike an issuer or endpoint, raw must
// already be in the URL's normalized string form, the one String gives
// back: a redirect goes to that string, and a registered redirect URI is
// matched exactly, so a spelling that would be rewritten, such as
// "HTTPS://RP.example/c b" for "https://rp.example/c%20b", is refused
// rather than sent somewhere other than the string registered.
func ParseRedirectURL(raw string, opts ...URLOption) (URL, error) {
	var o urlOptions
	for _, opt := range opts {
		opt(&o)
	}
	var u URL
	var err error
	if parsed, perr := url.Parse(raw); o.allowPrivateUseScheme && perr == nil && parsed.Scheme != "http" && parsed.Scheme != "https" && parsed.Scheme != "" {
		u, err = parsePrivateUseURL(raw, parsed)
	} else {
		u, err = parseSecureURL(raw, opts)
	}
	if err != nil {
		return URL{}, fmt.Errorf("fapi: parse redirect URL: %w", err)
	}
	// The redirect goes to u's string form, and the registered string is
	// what the client asked for: refuse one that differs, such as a
	// space net/url percent-encodes or an uppercase scheme or host it,
	// or parseSecureURL, lowercases.
	if sent := u.String(); sent != raw {
		return URL{}, fmt.Errorf("fapi: parse redirect URL: redirect URI must be written exactly as it is sent, %q: percent-encode any character RFC 3986 doesn't allow, and write the scheme and host in lowercase", sent)
	}
	if err := checkRedirectComponents(u.value); err != nil {
		return URL{}, fmt.Errorf("fapi: parse redirect URL: %w", err)
	}
	return u, nil
}

// CheckRedirectURIForm checks raw's form as a redirect URI, whatever its
// scheme, without deciding whether any client may use it: that it's
// written exactly as a redirect to it is sent (its normalized string
// form, scheme and host in lowercase), with RFC 3986 query text, no "."
// or ".." path segment and no empty or impossible port. It's what
// ParseRedirectURL also requires of every URI it accepts, and what
// storage.NewRegisteredClient holds each registered redirect URI to. A
// raw that doesn't parse as a URL at all passes, left for
// ParseRedirectURL to refuse where it's used.
func CheckRedirectURIForm(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	parsed.Host = canonical.LowerASCII(parsed.Host)
	if sent := parsed.String(); sent != raw {
		return fmt.Errorf("fapi: redirect URI must be written exactly as it is sent, %q: percent-encode any character RFC 3986 doesn't allow, and write the scheme and host in lowercase", sent)
	}
	if err := checkRedirectComponents(*parsed); err != nil {
		return fmt.Errorf("fapi: %w", err)
	}
	return nil
}

// checkRedirectComponents refuses what the string-form comparison in
// ParseRedirectURL lets through but a browser would still send
// differently, or not at all: a query with a character RFC 3986 §3.4
// doesn't allow, or a malformed percent-encoding (net/url gives a query
// back byte for byte, unchecked); a "." or ".." path segment, which a
// browser resolves away (RFC 3986 §5.2.4) before requesting the path;
// and a port that is empty or outside 1 to 65535.
func checkRedirectComponents(u url.URL) error {
	if !isQueryText(u.RawQuery) {
		return fmt.Errorf("redirect URI's query must be RFC 3986 query text: percent-encode any other character, and every %% as %%25")
	}
	for _, segment := range strings.Split(u.EscapedPath(), "/") {
		if s := strings.ToLower(segment); s == "." || s == ".." || s == "%2e" || s == "%2e%2e" || s == ".%2e" || s == "%2e." {
			return fmt.Errorf("redirect URI's path must not have a \".\" or \"..\" segment, which a browser resolves away")
		}
	}
	if u.Host != "" && strings.HasSuffix(u.Host, ":") {
		return fmt.Errorf("redirect URI's port must not be empty: leave out the \":\" for the default port")
	}
	if port := u.Port(); port != "" {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("redirect URI's port must be 1 to 65535")
		}
	}
	return nil
}

// isQueryText reports whether q is RFC 3986 §3.4 query text: unreserved
// characters, sub-delims, ":", "@", "/", "?", and %-encodings of two
// hex digits.
func isQueryText(q string) bool {
	for i := 0; i < len(q); i++ {
		c := q[i]
		switch {
		case c == '%':
			if i+2 >= len(q) || !isHex(q[i+1]) || !isHex(q[i+2]) {
				return false
			}
			i += 2
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case strings.IndexByte("-._~!$&'()*+,;=:@/?", c) >= 0:
		default:
			return false
		}
	}
	return true
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

// parsePrivateUseURL validates parsed, raw's parse, as a private-use
// URI scheme redirect (RFC 8252 §7.1, §8.4).
func parsePrivateUseURL(raw string, parsed *url.URL) (URL, error) {
	if !isReverseDomainScheme(parsed.Scheme) {
		return URL{}, fmt.Errorf("private-use scheme %q must be a reverse-order domain name, such as com.example.app", parsed.Scheme)
	}
	if parsed.Host != "" {
		// RFC 8252 §7.1 writes a single slash after the scheme, "as there
		// is no naming authority for private-use URI scheme redirects",
		// but that's its description, not a requirement: an authority
		// adds nothing another app claiming the scheme (§8.6) could use,
		// and the registered string is still matched exactly.
		if parsed.User != nil || !isPrivateUseAuthority(parsed.Host) {
			return URL{}, fmt.Errorf("private-use redirect URI's authority must be a name of lowercase letters, digits, \"-\", \".\", \"_\" and \"~\", with no userinfo, port or IP address (%s:/path is RFC 8252 §7.1's preferred form)", parsed.Scheme)
		}
	} else if parsed.Opaque != "" || parsed.User != nil || !strings.HasPrefix(parsed.Path, "/") || strings.HasPrefix(parsed.String(), parsed.Scheme+"://") {
		// com.example.app:/callback; not com.example.app:callback, with no
		// path, or com.example.app:///callback, an empty authority.
		return URL{}, fmt.Errorf("private-use redirect URI must be %s:/path, with a single slash after the scheme (RFC 8252 §7.1), or %s://name/path", parsed.Scheme, parsed.Scheme)
	}
	if hasFragment(raw) {
		return URL{}, fmt.Errorf("URL must not contain a fragment")
	}
	return URL{value: *parsed}, nil
}

// hasFragment reports whether raw has a fragment component, even an
// empty one: RFC 3986 §3.5's fragment is everything after the first
// "#", so "https://rp.example/cb#" has one. net/url parses that "#"
// away, leaving url.URL.Fragment empty, and a URL that kept it would
// drop it from its string form, silently rewriting the value.
func hasFragment(raw string) bool {
	return strings.Contains(raw, "#")
}

// isReverseDomainScheme reports whether scheme has the form RFC 8252
// §7.1 requires of a private-use URI scheme: a domain name in reverse
// order, at least two dot-separated labels, each of letters, digits and
// "-", none empty. A scheme with no "." is the one RFC 8252 §8.4 says to
// reject at a minimum.
func isReverseDomainScheme(scheme string) bool {
	labels := strings.Split(scheme, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !isLabelRune(r) {
				return false
			}
		}
	}
	return true
}

// isPrivateUseAuthority reports whether host, a private-use redirect
// URI's authority, is a non-empty name of lowercase ASCII letters,
// digits, "-",
// ".", "_" and "~" (RFC 3986 §2.3's unreserved characters) that isn't an
// IP address: one net/url gives back as written, with no port, and that
// can't be mistaken for a loopback or other network destination.
func isPrivateUseAuthority(host string) bool {
	if host == "" || net.ParseIP(host) != nil {
		return false
	}
	for _, r := range host {
		if 'A' <= r && r <= 'Z' || !isLabelRune(r) && r != '.' && r != '_' && r != '~' {
			return false
		}
	}
	return true
}

// isLabelRune reports whether r may appear in a domain-name label.
func isLabelRune(r rune) bool {
	return 'a' <= r && r <= 'z' || 'A' <= r && r <= 'Z' || '0' <= r && r <= '9' || r == '-'
}

// ParseIssuerURL parses and validates raw as an issuer identifier. On
// top of what ParseEndpointURL checks, it refuses a query component,
// even an empty one ("https://as.example/?"): RFC 8414 §2 and OpenID
// Connect Core §2 define the issuer as a URL with no query or fragment,
// and RFC 9207 and Discovery §3 compare it as an exact string, so a
// query would only give one issuer a second spelling.
func ParseIssuerURL(raw string, opts ...URLOption) (URL, error) {
	u, err := parseSecureURL(raw, opts)
	if err != nil {
		return URL{}, fmt.Errorf("fapi: parse issuer URL: %w", err)
	}
	if u.value.RawQuery != "" || u.value.ForceQuery {
		return URL{}, fmt.Errorf("fapi: parse issuer URL: URL must not contain a query")
	}
	return u, nil
}

// ParseEndpointURL parses and validates raw as an endpoint URL (e.g. a
// PAR, authorization or token endpoint).
func ParseEndpointURL(raw string, opts ...URLOption) (URL, error) {
	u, err := parseSecureURL(raw, opts)
	if err != nil {
		return URL{}, fmt.Errorf("fapi: parse endpoint URL: %w", err)
	}
	return u, nil
}

func parseSecureURL(raw string, opts []URLOption) (URL, error) {
	var o urlOptions
	for _, opt := range opts {
		opt(&o)
	}

	if raw == "" {
		return URL{}, fmt.Errorf("URL is empty")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return URL{}, fmt.Errorf("invalid URL: %w", err)
	}
	if !parsed.IsAbs() {
		return URL{}, fmt.Errorf("URL must be absolute")
	}
	if parsed.Host == "" {
		return URL{}, fmt.Errorf("URL must have a host (scheme %q)", parsed.Scheme)
	}
	// Host names compare case-insensitively in ASCII only. A non-ASCII
	// host is refused rather than lowercased: Unicode case mapping
	// folds some non-ASCII letters onto ASCII ones ("İ" to "i"), while
	// net/http dials the host through IDNA as another DNS name
	// altogether ("İbank.example" is "xn--ibank-7fd.example", not
	// "ibank.example"), so no lowercased spelling of it names where
	// requests go.
	if !canonical.IsASCII(parsed.Host) {
		return URL{}, fmt.Errorf("URL host %q is not ASCII: give an internationalized domain name in its xn-- A-label form", parsed.Host)
	}
	if parsed.User != nil {
		return URL{}, fmt.Errorf("URL must not contain embedded credentials")
	}
	if hasFragment(raw) {
		return URL{}, fmt.Errorf("URL must not contain a fragment")
	}

	switch parsed.Scheme {
	case "https":
	case "http":
		if !o.allowLoopbackHTTP || !isLoopbackHost(parsed.Hostname()) {
			return URL{}, fmt.Errorf("URL must use https")
		}
	default:
		return URL{}, fmt.Errorf("URL scheme must be https, got %q", parsed.Scheme)
	}

	parsed.Scheme = canonical.LowerASCII(parsed.Scheme)
	parsed.Host = canonical.LowerASCII(parsed.Host)
	return URL{value: *parsed}, nil
}

// isLoopbackHost reports whether hostname — a URL's Hostname(), with
// any port and IPv6 brackets already removed — names the loopback
// interface. Taking Host instead would miss a bracketed IPv6 literal
// with no port ("[::1]"), which net.SplitHostPort rejects.
func isLoopbackHost(hostname string) bool {
	if canonical.EqualFoldASCII(hostname, "localhost") {
		return true
	}
	ip := net.ParseIP(hostname)
	return ip != nil && ip.IsLoopback()
}

// String returns the URL's string form.
func (u URL) String() string {
	return u.value.String()
}

// MarshalJSON encodes u as its string form, per String(). It has no
// UnmarshalJSON counterpart: parsing a URL back out needs one of
// ParseIssuerURL/ParseEndpointURL's validation modes, a choice a generic
// decoder can't make on the caller's behalf.
func (u URL) MarshalJSON() ([]byte, error) {
	return json.Marshal(u.String())
}

// URL returns a copy of the underlying net/url.URL.
func (u URL) URL() url.URL {
	return u.value
}

// IsZero reports whether u is the unset zero value.
func (u URL) IsZero() bool {
	return u.value == url.URL{}
}

// WithQuery returns a copy of u with its query string replaced by
// query: any query u already had is dropped. To add parameters to an
// endpoint's own query, which RFC 6749 §3.1 has a client retain, use
// WithAddedQuery: rebuilding it from u.URL().Query() reorders it and
// drops what url.ParseQuery can't decode. It does not
// re-validate scheme, credentials or fragment, since replacing only the
// query string cannot reintroduce a problem ParseEndpointURL already
// ruled out on u; this is what lets a caller build on an endpoint URL
// parsed under AllowLoopbackHTTP() without having to know that option
// applied to reconstruct the result.
func (u URL) WithQuery(query url.Values) URL {
	out := u.value
	out.RawQuery = query.Encode()
	return URL{value: out}
}

// WithAddedQuery returns a copy of u with query's parameters added after
// its own query, which is kept byte for byte: RFC 6749 §3.1 and §3.1.2
// say an endpoint's query "MUST be retained when adding additional query
// parameters". A parameter query names that u's query already has is
// then sent twice; the caller keeps the two apart. Like WithQuery, it
// does not re-validate the rest of u.
func (u URL) WithAddedQuery(query url.Values) URL {
	out := u.value
	out.RawQuery = querystring.Append(out.RawQuery, query.Encode())
	return URL{value: out}
}

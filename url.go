package fapi

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/idfoundry/fapigo/internal/canonical"
	"github.com/idfoundry/fapigo/internal/querystring"
)

// URL is a validated, security-sensitive URL — an issuer identifier, an
// endpoint or a redirect destination. It can only be constructed via
// ParseIssuerURL, ParseEndpointURL or ParseRedirectURL, which enforce:
// absolute, HTTPS (except an explicitly enabled loopback exception, or a
// native app's private-use scheme for a redirect), no embedded
// credentials, no fragment, a host in ASCII (an internationalized
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
// app's private-use URI scheme redirect (RFC 8252 §7.1), such as
// "com.example.app:/oauth2redirect": a scheme that is a domain name in
// reverse order, so it contains a ".", then a single slash and the path,
// as RFC 8252 §7.1 writes it — not "com.example.app://oauth2redirect",
// whose "oauth2redirect" would be an authority. Enable it only for a client
// registered as a native app.
func AllowPrivateUseScheme() URLOption {
	return func(o *urlOptions) { o.allowPrivateUseScheme = true }
}

// ParseRedirectURL parses and validates raw as an OAuth redirect URI:
// https, like ParseEndpointURL, unless an option admits loopback http
// (AllowLoopbackHTTP) or a native app's private-use scheme
// (AllowPrivateUseScheme).
func ParseRedirectURL(raw string, opts ...URLOption) (URL, error) {
	var o urlOptions
	for _, opt := range opts {
		opt(&o)
	}
	if o.allowPrivateUseScheme {
		if parsed, err := url.Parse(raw); err == nil && parsed.Scheme != "http" && parsed.Scheme != "https" && parsed.Scheme != "" {
			u, err := parsePrivateUseURL(parsed)
			if err != nil {
				return URL{}, fmt.Errorf("fapi: parse redirect URL: %w", err)
			}
			return u, nil
		}
	}
	u, err := parseSecureURL(raw, opts)
	if err != nil {
		return URL{}, fmt.Errorf("fapi: parse redirect URL: %w", err)
	}
	return u, nil
}

// parsePrivateUseURL validates parsed as a private-use URI scheme
// redirect (RFC 8252 §7.1, §8.4).
func parsePrivateUseURL(parsed *url.URL) (URL, error) {
	if !isReverseDomainScheme(parsed.Scheme) {
		return URL{}, fmt.Errorf("private-use scheme %q must be a reverse-order domain name, such as com.example.app", parsed.Scheme)
	}
	// RFC 8252 §7.1: "only a single slash ("/") appears after the scheme
	// component" — com.example.app:/callback, not
	// com.example.app://callback, where "callback" would be an authority.
	if parsed.Opaque != "" || parsed.Host != "" || parsed.User != nil || !strings.HasPrefix(parsed.Path, "/") || strings.HasPrefix(parsed.Path, "//") || strings.HasPrefix(parsed.String(), parsed.Scheme+"://") {
		return URL{}, fmt.Errorf("private-use redirect URI must be %s:/path, with a single slash after the scheme (RFC 8252 §7.1), not %s://…", parsed.Scheme, parsed.Scheme)
	}
	if parsed.Fragment != "" {
		return URL{}, fmt.Errorf("URL must not contain a fragment")
	}
	return URL{value: *parsed}, nil
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

// isLabelRune reports whether r may appear in a domain-name label.
func isLabelRune(r rune) bool {
	return 'a' <= r && r <= 'z' || 'A' <= r && r <= 'Z' || '0' <= r && r <= '9' || r == '-'
}

// ParseIssuerURL parses and validates raw as an issuer identifier.
func ParseIssuerURL(raw string, opts ...URLOption) (URL, error) {
	u, err := parseSecureURL(raw, opts)
	if err != nil {
		return URL{}, fmt.Errorf("fapi: parse issuer URL: %w", err)
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
	if parsed.Fragment != "" {
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

package fapi

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// URL is a validated, security-sensitive URL — an issuer identifier, an
// endpoint or a redirect destination. It can only be constructed via
// ParseIssuerURL, ParseEndpointURL or ParseRedirectURL, which enforce:
// absolute, HTTPS (except an explicitly enabled loopback exception, or a
// native app's private-use scheme for a redirect), no embedded
// credentials, no fragment, and a normalized (lowercased) scheme and
// host.
type URL struct {
	value url.URL
}

type urlOptions struct {
	allowLoopbackHTTP     bool
	allowPrivateUseScheme bool
}

// URLOption configures ParseIssuerURL or ParseEndpointURL.
type URLOption func(*urlOptions)

// AllowLoopbackHTTP permits an http:// scheme when the host is a
// loopback address ("localhost", 127.0.0.0/8, or ::1). It exists for
// local development only and must never be enabled from configuration
// that could reach a production deployment by accident.
func AllowLoopbackHTTP() URLOption {
	return func(o *urlOptions) { o.allowLoopbackHTTP = true }
}

// AllowPrivateUseScheme permits, for ParseRedirectURL only, a native
// app's private-use URI scheme redirect (RFC 8252 §7.1), such as
// "com.example.app:/oauth2redirect": a scheme that is a domain name in
// reverse order, so it contains a ".", followed by a path and no
// authority, as RFC 8252 §7.1 writes it. Enable it only for a client
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
	if parsed.Opaque != "" || parsed.Host != "" || parsed.User != nil || !strings.HasPrefix(parsed.Path, "/") {
		return URL{}, fmt.Errorf("private-use redirect URI must be scheme:/path, with no authority")
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
	if !parsed.IsAbs() || parsed.Host == "" {
		return URL{}, fmt.Errorf("URL must be absolute")
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

	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = strings.ToLower(parsed.Host)
	return URL{value: *parsed}, nil
}

// isLoopbackHost reports whether hostname — a URL's Hostname(), with
// any port and IPv6 brackets already removed — names the loopback
// interface. Taking Host instead would miss a bracketed IPv6 literal
// with no port ("[::1]"), which net.SplitHostPort rejects.
func isLoopbackHost(hostname string) bool {
	if strings.EqualFold(hostname, "localhost") {
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
// query — for appending caller-supplied parameters (e.g. request_uri,
// client_id) to an already-validated endpoint URL. It does not
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

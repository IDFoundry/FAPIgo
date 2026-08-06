package fapi

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// URL is a validated, security-sensitive URL — an issuer identifier or
// an endpoint. It can only be constructed via ParseIssuerURL or
// ParseEndpointURL, which enforce: absolute, HTTPS (except an
// explicitly enabled loopback development exception), no embedded
// credentials, no fragment, and a normalized (lowercased) scheme and
// host.
type URL struct {
	value url.URL
}

type urlOptions struct {
	allowLoopbackHTTP bool
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
		if !o.allowLoopbackHTTP || !isLoopbackHost(parsed.Host) {
			return URL{}, fmt.Errorf("URL must use https")
		}
	default:
		return URL{}, fmt.Errorf("URL scheme must be https, got %q", parsed.Scheme)
	}

	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = strings.ToLower(parsed.Host)
	return URL{value: *parsed}, nil
}

func isLoopbackHost(host string) bool {
	h := host
	if hostOnly, _, err := net.SplitHostPort(host); err == nil {
		h = hostOnly
	}
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// String returns the URL's string form.
func (u URL) String() string {
	return u.value.String()
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

package fapihttp

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"
)

// TransportConfig bounds the hardened transport NewClient builds. None
// of these have an implicit default — NewClient rejects a zero value.
type TransportConfig struct {
	// DialTimeout bounds how long a single TCP connection attempt may
	// take.
	DialTimeout time.Duration

	// TLSHandshakeTimeout bounds how long the TLS handshake may take.
	TLSHandshakeTimeout time.Duration

	// AllowLoopbackHTTP permits dialing a loopback address, for local
	// development only — see fapi.AllowLoopbackHTTP. It never exempts
	// any other private, link-local, unspecified or multicast address.
	AllowLoopbackHTTP bool
}

// NewClient builds an *http.Client whose Transport resolves each host
// itself and validates every candidate address before dialing it —
// rejecting loopback (unless AllowLoopbackHTTP), private, link-local,
// unspecified and multicast addresses — and never follows a redirect on
// its own (CheckRedirect always returns http.ErrUseLastResponse), so
// Client.Fetch's own bounded, origin-checked redirect handling is the
// only place a redirect is ever followed.
//
// Passing the result as New's HTTPClient argument is the recommended way
// to get SSRF protection that also holds under DNS rebinding: Fetch's own
// URL/origin validation happens before each round trip, but the name
// could resolve to a different, disallowed address by the time the
// underlying transport actually dials it. This transport closes that gap
// by resolving once, validating every candidate address, and dialing
// only an address it already validated — never re-resolving the
// hostname at connect time.
func NewClient(cfg TransportConfig) (*http.Client, error) {
	if cfg.DialTimeout <= 0 {
		return nil, fmt.Errorf("fapihttp: transport config: dial timeout must be positive")
	}
	if cfg.TLSHandshakeTimeout <= 0 {
		return nil, fmt.Errorf("fapihttp: transport config: tls handshake timeout must be positive")
	}

	base := &net.Dialer{Timeout: cfg.DialTimeout}
	transport := &http.Transport{
		DialContext:         safeDialContext(base, cfg.AllowLoopbackHTTP),
		TLSHandshakeTimeout: cfg.TLSHandshakeTimeout,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:   true,
	}
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

// safeDialContext resolves addr's host itself (or accepts it directly if
// it's already an IP literal), validates every candidate address, and
// dials the first one that passes — so the address actually connected to
// is always one this function itself checked, never a name resolved a
// second time by the caller's dialer.
func safeDialContext(base *net.Dialer, allowLoopback bool) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}

		var candidates []net.IP
		if ip := net.ParseIP(host); ip != nil {
			candidates = []net.IP{ip}
		} else {
			resolved, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			for _, a := range resolved {
				candidates = append(candidates, a.IP)
			}
		}

		var lastErr = ErrSSRFBlocked
		for _, ip := range candidates {
			if disallowedIP(ip, allowLoopback) {
				continue
			}
			conn, dialErr := base.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if dialErr == nil {
				return conn, nil
			}
			lastErr = dialErr
		}
		return nil, lastErr
	}
}

// extraBlockedCIDRs are address ranges net.IP's own IsPrivate/
// IsLinkLocal*/IsUnspecified/IsMulticast checks don't cover, but which
// are still not appropriate targets for a server-initiated fetch:
// carrier-grade NAT, IETF protocol assignments, benchmarking space, and
// the reserved/broadcast range. Parsed once at init from literals that
// cannot fail to parse.
var extraBlockedCIDRs = func() []*net.IPNet {
	cidrs := []string{
		"100.64.0.0/10", // RFC 6598 CGNAT
		"192.0.0.0/24",  // RFC 6890 IETF protocol assignments
		"198.18.0.0/15", // RFC 2544 benchmarking
		"240.0.0.0/4",   // RFC 1112 reserved (includes 255.255.255.255)
	}
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic("fapihttp: invalid literal CIDR " + c + ": " + err.Error())
		}
		out = append(out, n)
	}
	return out
}()

// disallowedIP reports whether ip is not an acceptable target for a
// server-initiated fetch: loopback (unless allowLoopback), private,
// link-local, unspecified, multicast, or one of extraBlockedCIDRs.
func disallowedIP(ip net.IP, allowLoopback bool) bool {
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if ip.IsLoopback() {
		return !allowLoopback
	}
	if ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	for _, n := range extraBlockedCIDRs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

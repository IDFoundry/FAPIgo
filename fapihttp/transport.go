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
// carrier-grade NAT, IETF protocol assignments, benchmarking space, the
// reserved/broadcast range, "this network", and documentation ranges.
// Parsed once at init from literals that cannot fail to parse.
var extraBlockedCIDRs = func() []*net.IPNet {
	cidrs := []string{
		"0.0.0.0/8",       // RFC 1122 "this network" (IsUnspecified only catches the exact 0.0.0.0)
		"100.64.0.0/10",   // RFC 6598 CGNAT
		"192.0.0.0/24",    // RFC 6890 IETF protocol assignments
		"192.0.2.0/24",    // RFC 5737 TEST-NET-1 documentation
		"198.18.0.0/15",   // RFC 2544 benchmarking
		"198.51.100.0/24", // RFC 5737 TEST-NET-2 documentation
		"203.0.113.0/24",  // RFC 5737 TEST-NET-3 documentation
		"240.0.0.0/4",     // RFC 1112 reserved (includes 255.255.255.255)
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
// link-local, unspecified, multicast, one of extraBlockedCIDRs, or an
// IPv6 transition address that tunnels one of the above.
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
	// A NAT64/6to4/Teredo/IPv4-compatible address looks like ordinary
	// global-unicast IPv6 to every check above, but on a host with the
	// matching transition mechanism configured it dials straight
	// through to the IPv4 address it tunnels — which may itself be
	// loopback/private/link-local. Recursing here can only add a
	// block: a recursed 4-byte address never matches
	// embeddedIPv4's own prefix checks, so this can recurse at most
	// once.
	if embedded := embeddedIPv4(ip); embedded != nil {
		return disallowedIP(embedded, allowLoopback)
	}
	return false
}

// embeddedIPv4 returns the IPv4 address carried inside an IPv6
// transition address (NAT64 64:ff9b::/96, 6to4 2002::/16, Teredo
// 2001:0000::/32, ISATAP's 0000:5efe/0200:5efe interface identifier, or
// the deprecated IPv4-compatible ::a.b.c.d), or nil if ip is not one of
// those forms. These formats tunnel an IPv4 destination inside a
// global-unicast-looking IPv6 address, so on a host with the matching
// tunnel routing configured they can reach an internal IPv4 target that
// the plain IPv6 checks (IsPrivate/IsLinkLocal*/...) never flag. The
// result is only ever used to add a block, so an imperfect decode is
// fail-safe: the worst case is over-blocking an address that happens to
// decode to a private-looking v4.
func embeddedIPv4(ip net.IP) net.IP {
	b := ip.To16()
	if b == nil || ip.To4() != nil { // already IPv4 / IPv4-mapped, handled by the caller
		return nil
	}
	switch {
	case b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xff && b[3] == 0x9b &&
		isZero(b[4:12]): // NAT64 well-known prefix 64:ff9b::/96
		return net.IPv4(b[12], b[13], b[14], b[15])
	case b[0] == 0x20 && b[1] == 0x02: // 6to4 2002::/16 — gateway v4 in bytes 2-5 (RFC 3056)
		return net.IPv4(b[2], b[3], b[4], b[5])
	case b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x00 && b[3] == 0x00: // Teredo 2001:0000::/32 — client v4 in bytes 12-15, bit-inverted (RFC 4380)
		return net.IPv4(b[12]^0xff, b[13]^0xff, b[14]^0xff, b[15]^0xff)
	case (b[8] == 0x00 || b[8] == 0x02) && b[9] == 0x00 && b[10] == 0x5e && b[11] == 0xfe:
		// ISATAP (RFC 5214) — identified by its 0000:5efe or 0200:5efe
		// interface-identifier marker in bytes 8-11, not by prefix: an
		// ISATAP address can carry any unicast prefix (bytes 0-7, the
		// existing checks above already ran against it), only the
		// interface ID is fixed. Embeds the tunneled v4 in bytes 12-15.
		return net.IPv4(b[12], b[13], b[14], b[15])
	case isZero(b[0:12]): // deprecated IPv4-compatible ::a.b.c.d (::/96); ::  and ::1 are already handled by the caller
		return net.IPv4(b[12], b[13], b[14], b[15])
	}
	return nil
}

// isZero reports whether every byte in b is zero.
func isZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

package fapi

import (
	"net"
	"net/url"
	"strings"
	"testing"
)

// FuzzParseEndpointURL checks the invariants every issuer, endpoint and
// redirect destination in this module relies on ParseEndpointURL (and
// ParseIssuerURL, which shares parseSecureURL) to enforce — including
// on a client-supplied redirect_uri, which a pushed authorization
// request now runs through it. Beyond "does not panic":
//
//   - an accepted URL is absolute, has no credentials or fragment, and
//     has a lowercase scheme and host;
//   - it is https, or http only with AllowLoopbackHTTP and a host that
//     is genuinely loopback — judged by an oracle independent of
//     isLoopbackHost (url.Hostname, which strips the port and IPv6
//     brackets itself);
//   - conversely, an http URL with a genuinely loopback host that is
//     otherwise valid is accepted under AllowLoopbackHTTP, so the
//     option isn't silently narrower than documented;
//   - AllowLoopbackHTTP only ever widens what's accepted;
//   - re-parsing String() is a fixed point.
func FuzzParseEndpointURL(f *testing.F) {
	for _, seed := range []string{
		"https://as.example/par",
		"HTTPS://AS.Example:443/Path?q=1",
		"http://localhost:8080/callback",
		"http://LOCALHOST/cb",
		"http://127.0.0.1/cb",
		"http://[::1]/cb",
		"http://[::1]:8080/cb",
		"http://[::ffff:127.0.0.1]:80/cb",
		"http://localhost.evil.example/cb",
		"http://evil.example/cb?localhost",
		"http://127.0.0.1.nip.io/cb",
		"http://user@localhost/cb",
		"https://as.example/cb#frag",
		"javascript:alert(1)",
		"//as.example/x",
		"",
	} {
		f.Add(seed, true)
		f.Add(seed, false)
	}

	f.Fuzz(func(t *testing.T, raw string, allowLoopback bool) {
		var opts []URLOption
		if allowLoopback {
			opts = append(opts, AllowLoopbackHTTP())
		}
		u, err := ParseEndpointURL(raw, opts...)

		if err != nil {
			checkLoopbackHTTPNotWronglyRejected(t, raw, allowLoopback)
			return
		}
		checkAcceptedURL(t, raw, u, allowLoopback)

		if !allowLoopback {
			if _, err := ParseEndpointURL(raw, AllowLoopbackHTTP()); err != nil {
				t.Fatalf("%q accepted without AllowLoopbackHTTP but rejected with it: %v", raw, err)
			}
		}

		again, err := ParseEndpointURL(u.String(), opts...)
		if err != nil {
			t.Fatalf("String() of accepted %q is %q, which no longer parses: %v", raw, u.String(), err)
		}
		if again.String() != u.String() {
			t.Fatalf("re-parsing is not a fixed point for %q: %q then %q", raw, u.String(), again.String())
		}
	})
}

func checkAcceptedURL(t *testing.T, raw string, u URL, allowLoopback bool) {
	t.Helper()
	parsed := u.URL()
	if !parsed.IsAbs() || parsed.Host == "" {
		t.Fatalf("accepted non-absolute URL %q", raw)
	}
	if parsed.User != nil {
		t.Fatalf("accepted URL with credentials %q", raw)
	}
	if parsed.Fragment != "" {
		t.Fatalf("accepted URL with fragment %q", raw)
	}
	if parsed.Scheme != strings.ToLower(parsed.Scheme) || parsed.Host != strings.ToLower(parsed.Host) {
		t.Fatalf("accepted %q without lowercasing scheme/host: %q", raw, u.String())
	}
	switch parsed.Scheme {
	case "https":
	case "http":
		if !allowLoopback {
			t.Fatalf("accepted http URL %q without AllowLoopbackHTTP", raw)
		}
		if !loopbackOracle(parsed.Hostname()) {
			t.Fatalf("accepted http URL %q whose host %q is not loopback", raw, parsed.Hostname())
		}
	default:
		t.Fatalf("accepted scheme %q in %q", parsed.Scheme, raw)
	}
}

// checkLoopbackHTTPNotWronglyRejected fails if raw was rejected even
// though it is an otherwise-valid http URL whose host is loopback and
// AllowLoopbackHTTP was given.
func checkLoopbackHTTPNotWronglyRejected(t *testing.T, raw string, allowLoopback bool) {
	t.Helper()
	if !allowLoopback {
		return
	}
	parsed, err := url.Parse(raw)
	if err != nil || !strings.EqualFold(parsed.Scheme, "http") || !parsed.IsAbs() || parsed.Host == "" ||
		parsed.User != nil || parsed.Fragment != "" {
		return
	}
	if loopbackOracle(parsed.Hostname()) {
		t.Fatalf("rejected loopback http URL %q (host %q) under AllowLoopbackHTTP", raw, parsed.Hostname())
	}
}

func loopbackOracle(hostname string) bool {
	if strings.EqualFold(hostname, "localhost") {
		return true
	}
	ip := net.ParseIP(hostname)
	return ip != nil && ip.IsLoopback()
}

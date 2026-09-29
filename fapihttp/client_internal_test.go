package fapihttp

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// fakeIPResolver returns results[min(calls, len(results)-1)] on each
// call, so a test can script "safe IP on the first resolution, blocked
// IP on the next" to exercise checkHostIPs on a redirect hop
// independently of the initial request's hop.
type fakeIPResolver struct {
	calls   int
	results [][]net.IP
}

func (f *fakeIPResolver) resolve(_ context.Context, _ string) ([]net.IP, error) {
	i := f.calls
	if i >= len(f.results) {
		i = len(f.results) - 1
	}
	f.calls++
	return f.results[i], nil
}

// failIfCalledHTTPClient fails the test if Do is ever invoked — used to
// prove a fetch was rejected before any dial was attempted.
type failIfCalledHTTPClient struct{ t *testing.T }

func (f failIfCalledHTTPClient) Do(*http.Request) (*http.Response, error) {
	f.t.Helper()
	f.t.Fatalf("HTTPClient.Do called; want the fetch blocked before any round trip")
	return nil, nil
}

// sequencedHTTPClient returns responses[0], responses[1], ... in order,
// failing the test if called more times than there are responses.
type sequencedHTTPClient struct {
	t         *testing.T
	responses []*http.Response
	calls     int
}

func (c *sequencedHTTPClient) Do(*http.Request) (*http.Response, error) {
	c.t.Helper()
	if c.calls >= len(c.responses) {
		c.t.Fatalf("Do called more times (%d) than expected (%d)", c.calls+1, len(c.responses))
	}
	res := c.responses[c.calls]
	c.calls++
	return res, nil
}

func mustParseTestURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", raw, err)
	}
	return u
}

// TestFetchRejectsHTTPSResolvingToLoopback documents H-2 Part B: even
// though the URL's scheme/host shape is valid https, Fetch's own
// pre-dial check rejects a host that resolves to a disallowed address —
// here, before any round trip is attempted at all.
func TestFetchRejectsHTTPSResolvingToLoopback(t *testing.T) {
	resolver := &fakeIPResolver{results: [][]net.IP{{net.ParseIP("127.0.0.1")}}}
	c := &Client{
		http:       failIfCalledHTTPClient{t: t},
		cfg:        Config{MaxResponseBytes: 1024, RequestTimeout: 5 * time.Second, MaxRedirects: 1},
		resolveIPs: resolver.resolve,
	}
	_, err := c.Fetch(context.Background(), FetchRequest{
		URL:                 mustParseTestURL(t, "https://issuer.example.com/jwks"),
		ExpectedContentType: "application/json",
	})
	if !errors.Is(err, ErrSSRFBlocked) {
		t.Fatalf("Fetch error = %v, want ErrSSRFBlocked", err)
	}
}

// TestFetchAllowsPrivateIPForAllowedHost proves Config.AllowedPrivateHosts
// lets Fetch through for a host that resolves to a private address, when
// (and only when) that exact host is on the list — a real docker-compose
// peer-service scenario, not the fixed loopback address every other
// pre-dial-check test here uses.
func TestFetchAllowsPrivateIPForAllowedHost(t *testing.T) {
	resolver := &fakeIPResolver{results: [][]net.IP{{net.ParseIP("10.0.0.5")}}}
	okResp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader("{}")),
		TLS:        &tls.ConnectionState{},
	}
	c := &Client{
		http: &sequencedHTTPClient{t: t, responses: []*http.Response{okResp}},
		cfg: Config{
			MaxResponseBytes: 1024, RequestTimeout: 5 * time.Second, MaxRedirects: 1,
			AllowedPrivateHosts: []string{"internal.test"},
		},
		resolveIPs: resolver.resolve,
	}
	_, err := c.Fetch(context.Background(), FetchRequest{
		URL:                 mustParseTestURL(t, "https://internal.test/a"),
		ExpectedContentType: "application/json",
	})
	if err != nil {
		t.Fatalf("Fetch error = %v, want nil (internal.test is on AllowedPrivateHosts)", err)
	}
}

// TestFetchRejectsPrivateIPForHostNotAllowed proves
// Config.AllowedPrivateHosts is exact-match, not a blanket exemption: a
// different private-resolving host, absent from the list, is still
// blocked.
func TestFetchRejectsPrivateIPForHostNotAllowed(t *testing.T) {
	resolver := &fakeIPResolver{results: [][]net.IP{{net.ParseIP("10.0.0.5")}}}
	c := &Client{
		http: failIfCalledHTTPClient{t: t},
		cfg: Config{
			MaxResponseBytes: 1024, RequestTimeout: 5 * time.Second, MaxRedirects: 1,
			AllowedPrivateHosts: []string{"some-other-host.test"},
		},
		resolveIPs: resolver.resolve,
	}
	_, err := c.Fetch(context.Background(), FetchRequest{
		URL:                 mustParseTestURL(t, "https://internal.test/a"),
		ExpectedContentType: "application/json",
	})
	if !errors.Is(err, ErrSSRFBlocked) {
		t.Fatalf("Fetch error = %v, want ErrSSRFBlocked", err)
	}
}

// TestFetchRejectsRedirectToInternalIP proves the same pre-dial IP
// check applies to every redirect hop, not only the initial request:
// the first resolution of the (same) hostname is safe, so the initial
// request proceeds and receives a same-origin redirect; the second
// resolution of that hostname — made when validating the redirect
// target — comes back private, and the redirect is rejected before
// it's ever followed.
func TestFetchRejectsRedirectToInternalIP(t *testing.T) {
	resolver := &fakeIPResolver{results: [][]net.IP{
		{net.ParseIP("93.184.216.34")}, // initial hop: public, allowed
		{net.ParseIP("10.0.0.5")},      // redirect hop: private, blocked
	}}
	redirectResp := &http.Response{
		StatusCode: http.StatusFound,
		Header:     http.Header{"Location": []string{"https://internal.test/b"}},
		Body:       io.NopCloser(strings.NewReader("")),
		TLS:        &tls.ConnectionState{},
	}
	c := &Client{
		http:       &sequencedHTTPClient{t: t, responses: []*http.Response{redirectResp}},
		cfg:        Config{MaxResponseBytes: 1024, RequestTimeout: 5 * time.Second, MaxRedirects: 1},
		resolveIPs: resolver.resolve,
	}
	_, err := c.Fetch(context.Background(), FetchRequest{
		URL:                 mustParseTestURL(t, "https://internal.test/a"),
		ExpectedContentType: "application/json",
	})
	if !errors.Is(err, ErrSSRFBlocked) {
		t.Fatalf("Fetch error = %v, want ErrSSRFBlocked", err)
	}
}

// TestIsLoopbackHostTakesHostname covers the IPv6 case
// FuzzParseEndpointURL found in fapi's identical helper: a bracketed
// literal with no port is loopback too, once Hostname() has removed
// the brackets.
func TestIsLoopbackHostTakesHostname(t *testing.T) {
	for _, raw := range []string{"http://[::1]/x", "http://[::1]:8080/x", "http://localhost/x", "http://127.0.0.1:1/x"} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("url.Parse(%q): %v", raw, err)
		}
		if !isLoopbackHost(u.Hostname()) {
			t.Errorf("isLoopbackHost(%q) = false, want true", u.Hostname())
		}
	}
	if isLoopbackHost("localhost.evil.example") {
		t.Errorf("isLoopbackHost(localhost.evil.example) = true, want false")
	}
}

// TestLoopbackPolicy covers which hosts may reach a loopback address:
// literal loopback hosts (with AllowLoopbackHosts or AllowLoopbackHTTP)
// and listed names — never an arbitrary name that resolves there.
func TestLoopbackPolicy(t *testing.T) {
	literal := loopbackPolicy{literalHosts: true}
	for _, host := range []string{"localhost", "LOCALHOST", "id.eastmark.localhost", "127.0.0.1", "127.9.9.9", "::1"} {
		if !literal.permits(host) {
			t.Errorf("literal policy permits(%q) = false, want true", host)
		}
	}
	for _, host := range []string{"evil.example", "localhost.evil.example", "localhost-evil.example", "10.0.0.1"} {
		if literal.permits(host) {
			t.Errorf("literal policy permits(%q) = true, want false", host)
		}
	}
	if (loopbackPolicy{}).permits("localhost") {
		t.Error("zero policy permits(localhost) = true, want false")
	}
	named := loopbackPolicy{named: []string{"suite.example"}}
	if !named.permits("SUITE.example") || named.permits("localhost") || named.permits("other.example") {
		t.Error("named policy should permit exactly its listed host")
	}
}

// TestFetchLoopbackRules covers Fetch's pre-dial check under each
// loopback setting, including the case the split exists for: a name
// that merely resolves to 127.0.0.1 is blocked by AllowLoopbackHTTP and
// AllowLoopbackHosts alike, and allowed only when listed.
func TestFetchLoopbackRules(t *testing.T) {
	loopbackIP := []net.IP{net.ParseIP("127.0.0.1")}
	for _, tc := range []struct {
		name string
		cfg  Config
		url  string
		ips  []net.IP
		want error
	}{
		{"nothing set, https literal", Config{}, "https://127.0.0.1/jwks", nil, ErrSSRFBlocked},
		{"hosts, https literal", Config{AllowLoopbackHosts: true}, "https://127.0.0.1/jwks", nil, nil},
		{"hosts, https .localhost", Config{AllowLoopbackHosts: true}, "https://id.eastmark.localhost/jwks", loopbackIP, nil},
		{"hosts, http literal", Config{AllowLoopbackHosts: true}, "http://127.0.0.1/jwks", nil, ErrInsecureURL},
		{"http, http literal", Config{AllowLoopbackHTTP: true}, "http://localhost/jwks", loopbackIP, nil},
		{"http, https literal", Config{AllowLoopbackHTTP: true}, "https://[::1]/jwks", nil, nil},
		{"http, https name resolving to loopback", Config{AllowLoopbackHTTP: true}, "https://evil.example/jwks", loopbackIP, ErrSSRFBlocked},
		{"hosts, https name resolving to loopback", Config{AllowLoopbackHosts: true}, "https://evil.example/jwks", loopbackIP, ErrSSRFBlocked},
		{"listed, https name resolving to loopback", Config{AllowedLoopbackHosts: []string{"suite.example"}}, "https://suite.example/jwks", loopbackIP, nil},
		{"listed, http without AllowLoopbackHTTP", Config{AllowedLoopbackHosts: []string{"suite.example"}}, "http://suite.example/jwks", loopbackIP, ErrInsecureURL},
		{"listed, only loopback lifted", Config{AllowedLoopbackHosts: []string{"suite.example"}}, "https://suite.example/jwks", []net.IP{net.ParseIP("10.0.0.5")}, ErrSSRFBlocked},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.cfg.MaxResponseBytes, tc.cfg.RequestTimeout, tc.cfg.MaxRedirects = 1024, 5*time.Second, 1
			c := &Client{
				http: failIfCalledHTTPClient{t: t}, cfg: tc.cfg,
				resolveIPs: func(context.Context, string) ([]net.IP, error) { return tc.ips, nil },
			}
			err := c.validateFetchURL(context.Background(), mustParseTestURL(t, tc.url))
			if !errors.Is(err, tc.want) || (tc.want == nil && err != nil) {
				t.Errorf("validateFetchURL = %v, want %v", err, tc.want)
			}
		})
	}
}

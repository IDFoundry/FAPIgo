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

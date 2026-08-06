package fapihttp_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/osanderson/go-fapi/fapihttp"
)

func validConfig() fapihttp.Config {
	return fapihttp.Config{
		MaxResponseBytes: 1024,
		RequestTimeout:   5 * time.Second,
		MaxRedirects:     1,
	}
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", raw, err)
	}
	return u
}

// noRedirectClient returns ts.Client() with automatic redirect-following
// disabled. A caller of fapihttp.New is documented to supply a client
// shaped like this (see Client's doc comment and NewClient, which always
// sets this same policy) precisely so Client.Fetch's own bounded,
// origin-checked redirect handling is the only place a redirect is ever
// followed — using ts.Client() directly here would let the stdlib
// silently follow the redirect before Fetch's loop ever saw the 3xx
// status, testing net/http's redirect behavior instead of fapihttp's.
func noRedirectClient(ts *httptest.Server) *http.Client {
	c := ts.Client()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return c
}

func TestNewRejectsInvalidConfig(t *testing.T) {
	cases := map[string]func(*fapihttp.Config){
		"zero max response bytes": func(c *fapihttp.Config) { c.MaxResponseBytes = 0 },
		"zero request timeout":    func(c *fapihttp.Config) { c.RequestTimeout = 0 },
		"negative max redirects":  func(c *fapihttp.Config) { c.MaxRedirects = -1 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := validConfig()
			mutate(&cfg)
			if _, err := fapihttp.New(http.DefaultClient, cfg); err == nil {
				t.Fatalf("New(%s) = nil error, want error", name)
			}
		})
	}
}

func TestNewRejectsNilHTTPClient(t *testing.T) {
	if _, err := fapihttp.New(nil, validConfig()); err == nil {
		t.Fatalf("New(nil client) = nil error, want error")
	}
}

func TestFetchAcceptsValidResponse(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()

	c, err := fapihttp.New(ts.Client(), validConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res, err := c.Fetch(context.Background(), fapihttp.FetchRequest{
		URL:                 mustParseURL(t, ts.URL),
		ExpectedContentType: "application/json",
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(res.Body) != `{"ok":true}` {
		t.Errorf("Body = %q, want %q", res.Body, `{"ok":true}`)
	}
	if res.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", res.StatusCode)
	}
}

func TestFetchRejectsContentTypeMismatch(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(`not json`))
	}))
	defer ts.Close()

	c, err := fapihttp.New(ts.Client(), validConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = c.Fetch(context.Background(), fapihttp.FetchRequest{
		URL:                 mustParseURL(t, ts.URL),
		ExpectedContentType: "application/json",
	})
	if err == nil {
		t.Fatalf("Fetch = nil error, want error")
	}
}

func TestFetchRejectsOversizedBody(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(strings.Repeat("a", 2048)))
	}))
	defer ts.Close()

	cfg := validConfig()
	cfg.MaxResponseBytes = 16
	c, err := fapihttp.New(ts.Client(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = c.Fetch(context.Background(), fapihttp.FetchRequest{
		URL:                 mustParseURL(t, ts.URL),
		ExpectedContentType: "application/json",
	})
	if err == nil {
		t.Fatalf("Fetch = nil error, want error")
	}
}

func TestFetchRejectsNonOKStatus(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{}`))
	}))
	defer ts.Close()

	c, err := fapihttp.New(ts.Client(), validConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = c.Fetch(context.Background(), fapihttp.FetchRequest{
		URL:                 mustParseURL(t, ts.URL),
		ExpectedContentType: "application/json",
	})
	if err == nil {
		t.Fatalf("Fetch = nil error, want error")
	}
}

func TestFetchFollowsSameOriginRedirectWithinBound(t *testing.T) {
	var ts *httptest.Server
	ts = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/a" {
			http.Redirect(w, r, ts.URL+"/b", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"hop":"b"}`))
	}))
	defer ts.Close()

	c, err := fapihttp.New(noRedirectClient(ts), validConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res, err := c.Fetch(context.Background(), fapihttp.FetchRequest{
		URL:                 mustParseURL(t, ts.URL+"/a"),
		ExpectedContentType: "application/json",
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(res.Body) != `{"hop":"b"}` {
		t.Errorf("Body = %q, want %q", res.Body, `{"hop":"b"}`)
	}
}

func TestFetchRejectsRedirectBeyondBound(t *testing.T) {
	var ts *httptest.Server
	ts = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, ts.URL+"/b", http.StatusFound)
	}))
	defer ts.Close()

	cfg := validConfig()
	cfg.MaxRedirects = 0
	c, err := fapihttp.New(noRedirectClient(ts), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = c.Fetch(context.Background(), fapihttp.FetchRequest{
		URL:                 mustParseURL(t, ts.URL+"/a"),
		ExpectedContentType: "application/json",
	})
	if !errors.Is(err, fapihttp.ErrTooManyRedirects) {
		t.Fatalf("Fetch error = %v, want ErrTooManyRedirects", err)
	}
}

func TestFetchRejectsCrossOriginRedirect(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://evil.example.com/steal", http.StatusFound)
	}))
	defer ts.Close()

	c, err := fapihttp.New(noRedirectClient(ts), validConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = c.Fetch(context.Background(), fapihttp.FetchRequest{
		URL:                 mustParseURL(t, ts.URL),
		ExpectedContentType: "application/json",
	})
	if !errors.Is(err, fapihttp.ErrRedirectOriginMismatch) {
		t.Fatalf("Fetch error = %v, want ErrRedirectOriginMismatch", err)
	}
}

func TestFetchRejectsInsecureURLByDefault(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
	}))
	defer ts.Close()

	c, err := fapihttp.New(ts.Client(), validConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = c.Fetch(context.Background(), fapihttp.FetchRequest{
		URL:                 mustParseURL(t, ts.URL),
		ExpectedContentType: "application/json",
	})
	if err == nil {
		t.Fatalf("Fetch(plain http) = nil error, want error")
	}
}

func TestFetchAllowsLoopbackHTTPWhenConfigured(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
	}))
	defer ts.Close()

	cfg := validConfig()
	cfg.AllowLoopbackHTTP = true
	c, err := fapihttp.New(ts.Client(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.Fetch(context.Background(), fapihttp.FetchRequest{
		URL:                 mustParseURL(t, ts.URL),
		ExpectedContentType: "application/json",
	}); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
}

// fakeHTTPClient lets a test fabricate a response without any real
// network round trip — used here to simulate an https response that
// somehow carries no TLS connection state, which a genuine network round
// trip can't be made to produce on demand.
type fakeHTTPClient struct {
	response *http.Response
}

func (f *fakeHTTPClient) Do(*http.Request) (*http.Response, error) {
	return f.response, nil
}

func TestFetchRejectsMissingTLSState(t *testing.T) {
	fake := &fakeHTTPClient{response: &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{}`)),
		TLS:        nil,
	}}
	c, err := fapihttp.New(fake, validConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = c.Fetch(context.Background(), fapihttp.FetchRequest{
		URL:                 mustParseURL(t, "https://as.example.com/jwks"),
		ExpectedContentType: "application/json",
	})
	if err == nil {
		t.Fatalf("Fetch(no TLS state) = nil error, want error")
	}
}

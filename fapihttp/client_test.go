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

	"github.com/idfoundry/fapigo/fapihttp"
)

func validConfig() fapihttp.Config {
	return fapihttp.Config{
		MaxResponseBytes: 1024,
		RequestTimeout:   5 * time.Second,
		MaxRedirects:     1,
	}
}

// validLoopbackConfig is validConfig with AllowLoopbackHTTP set, for
// tests that legitimately target a local httptest server: since H-2's
// pre-dial IP check blocks loopback addresses by default (the same as
// NewClient's dial-time protection), a test hitting 127.0.0.1 needs to
// opt in, just as a real deployment pointing at a loopback issuer would.
func validLoopbackConfig() fapihttp.Config {
	cfg := validConfig()
	cfg.AllowLoopbackHTTP = true
	return cfg
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

	c, err := fapihttp.New(ts.Client(), validLoopbackConfig())
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

	c, err := fapihttp.New(ts.Client(), validLoopbackConfig())
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

// TestFetchAcceptsAlternateContentType covers a response whose
// Content-Type matches one of AlternateContentTypes rather than
// ExpectedContentType — e.g. a JWKS document served as
// "application/jwk-set+json" instead of "application/json".
func TestFetchAcceptsAlternateContentType(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/jwk-set+json")
		w.Write([]byte(`{"keys":[]}`))
	}))
	defer ts.Close()

	c, err := fapihttp.New(ts.Client(), validLoopbackConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res, err := c.Fetch(context.Background(), fapihttp.FetchRequest{
		URL:                   mustParseURL(t, ts.URL),
		ExpectedContentType:   "application/json",
		AlternateContentTypes: []string{"application/jwk-set+json"},
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(res.Body) != `{"keys":[]}` {
		t.Errorf("Body = %q, want %q", res.Body, `{"keys":[]}`)
	}
}

// TestFetchRejectsUnlistedAlternateContentType confirms
// AlternateContentTypes doesn't loosen the check into accepting
// anything — only a listed alternate is accepted, everything else still
// fails exactly as before.
func TestFetchRejectsUnlistedAlternateContentType(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(`not json`))
	}))
	defer ts.Close()

	c, err := fapihttp.New(ts.Client(), validLoopbackConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = c.Fetch(context.Background(), fapihttp.FetchRequest{
		URL:                   mustParseURL(t, ts.URL),
		ExpectedContentType:   "application/json",
		AlternateContentTypes: []string{"application/jwk-set+json"},
	})
	if !errors.Is(err, fapihttp.ErrUnexpectedContentType) {
		t.Fatalf("Fetch error = %v, want ErrUnexpectedContentType", err)
	}
}

// TestFetchRejectsMissingContentType covers checkContentType's other
// rejection branch — TestFetchRejectsContentTypeMismatch only ever
// exercises a present-but-wrong Content-Type; a response with no
// Content-Type header at all had no test of its own.
func TestFetchRejectsMissingContentType(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{}`))
	}))
	defer ts.Close()

	c, err := fapihttp.New(ts.Client(), validLoopbackConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = c.Fetch(context.Background(), fapihttp.FetchRequest{
		URL:                 mustParseURL(t, ts.URL),
		ExpectedContentType: "application/json",
	})
	if !errors.Is(err, fapihttp.ErrUnexpectedContentType) {
		t.Fatalf("Fetch error = %v, want ErrUnexpectedContentType", err)
	}
}

func TestFetchRejectsOversizedBody(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(strings.Repeat("a", 2048)))
	}))
	defer ts.Close()

	cfg := validLoopbackConfig()
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

	c, err := fapihttp.New(ts.Client(), validLoopbackConfig())
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

	c, err := fapihttp.New(noRedirectClient(ts), validLoopbackConfig())
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

	cfg := validLoopbackConfig()
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

	c, err := fapihttp.New(noRedirectClient(ts), validLoopbackConfig())
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

// TestFetchRejectsEmbeddedCredentials covers validateFetchURL's
// embedded-credentials rejection, which had no test of its own. The
// target server is real and reachable — if the check were bypassed,
// the request would actually succeed and hit it — so this proves
// validateFetchURL itself is what rejects the URL, not an incidental
// network failure.
func TestFetchRejectsEmbeddedCredentials(t *testing.T) {
	var hit bool
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
	}))
	defer ts.Close()

	c, err := fapihttp.New(ts.Client(), validConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	u := mustParseURL(t, ts.URL)
	u.User = url.UserPassword("user", "pass")
	_, err = c.Fetch(context.Background(), fapihttp.FetchRequest{
		URL:                 u,
		ExpectedContentType: "application/json",
	})
	if err == nil {
		t.Fatalf("Fetch(embedded credentials) = nil error, want error")
	}
	if hit {
		t.Fatalf("Fetch(embedded credentials) reached the server, want rejected before any request")
	}
}

// TestFetchStdlibClientDoesNotReachLoopback documents H-2: even a
// caller that ignores the HTTPClient doc comment's recommendation and
// passes a stock http.DefaultClient (with no SSRF-hardened transport)
// still gets loopback blocked, because Fetch's own best-effort pre-dial
// check runs regardless of which HTTPClient the caller supplied.
func TestFetchStdlibClientDoesNotReachLoopback(t *testing.T) {
	c, err := fapihttp.New(http.DefaultClient, validConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = c.Fetch(context.Background(), fapihttp.FetchRequest{
		URL:                 mustParseURL(t, "https://127.0.0.1:1/jwks"),
		ExpectedContentType: "application/json",
	})
	if !errors.Is(err, fapihttp.ErrSSRFBlocked) {
		t.Fatalf("Fetch(http.DefaultClient, loopback IP literal) error = %v, want ErrSSRFBlocked", err)
	}
}

func TestFetchAllowsLoopbackHTTPWhenConfigured(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
	}))
	defer ts.Close()

	c, err := fapihttp.New(ts.Client(), validLoopbackConfig())
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
	// An IP literal (rather than a hostname fapihttp would otherwise have
	// to resolve) so this test's SSRF pre-check needs no real DNS lookup
	// and stays hermetic; 1.1.1.1 is a stable public address, so the
	// check passes and the fake client's TLS-less response is what's
	// actually under test.
	_, err = c.Fetch(context.Background(), fapihttp.FetchRequest{
		URL:                 mustParseURL(t, "https://1.1.1.1/jwks"),
		ExpectedContentType: "application/json",
	})
	if err == nil {
		t.Fatalf("Fetch(no TLS state) = nil error, want error")
	}
}

func TestPostSendsBodyAndContentType(t *testing.T) {
	var gotMethod, gotContentType, gotBody string
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotContentType = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/trust-mark-status-response+jwt")
		w.Write([]byte("a.b.c"))
	}))
	defer ts.Close()

	c, err := fapihttp.New(ts.Client(), validLoopbackConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res, err := c.Post(context.Background(), fapihttp.PostRequest{
		URL:                 mustParseURL(t, ts.URL),
		Body:                []byte("trust_mark=abc"),
		ContentType:         "application/x-www-form-urlencoded",
		ExpectedContentType: "application/trust-mark-status-response+jwt",
	})
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	if string(res.Body) != "a.b.c" {
		t.Errorf("Body = %q, want %q", res.Body, "a.b.c")
	}
	if gotMethod != http.MethodPost {
		t.Errorf("server saw method %q, want POST", gotMethod)
	}
	if gotContentType != "application/x-www-form-urlencoded" {
		t.Errorf("server saw Content-Type %q, want application/x-www-form-urlencoded", gotContentType)
	}
	if gotBody != "trust_mark=abc" {
		t.Errorf("server saw body %q, want %q", gotBody, "trust_mark=abc")
	}
}

func TestPostRejectsMissingFields(t *testing.T) {
	c, err := fapihttp.New(http.DefaultClient, validConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cases := map[string]fapihttp.PostRequest{
		"no url":                   {ContentType: "application/x-www-form-urlencoded", ExpectedContentType: "application/json"},
		"no content type":          {URL: mustParseURL(t, "https://example.org"), ExpectedContentType: "application/json"},
		"no expected content type": {URL: mustParseURL(t, "https://example.org"), ContentType: "application/x-www-form-urlencoded"},
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := c.Post(context.Background(), req); err == nil {
				t.Fatalf("Post(%s) = nil error, want error", name)
			}
		})
	}
}

func TestPostRejectsContentTypeMismatch(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("not the expected type"))
	}))
	defer ts.Close()

	c, err := fapihttp.New(ts.Client(), validLoopbackConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = c.Post(context.Background(), fapihttp.PostRequest{
		URL: mustParseURL(t, ts.URL), Body: []byte("x=1"),
		ContentType: "application/x-www-form-urlencoded", ExpectedContentType: "application/json",
	})
	if err == nil {
		t.Fatalf("Post = nil error, want error")
	}
}

func TestPostRejectsOversizedBody(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(strings.Repeat("a", 2048)))
	}))
	defer ts.Close()

	cfg := validLoopbackConfig()
	cfg.MaxResponseBytes = 16
	c, err := fapihttp.New(ts.Client(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = c.Post(context.Background(), fapihttp.PostRequest{
		URL: mustParseURL(t, ts.URL), Body: []byte("x=1"),
		ContentType: "application/x-www-form-urlencoded", ExpectedContentType: "application/json",
	})
	if err == nil {
		t.Fatalf("Post = nil error, want error")
	}
}

func TestPostRejectsNonOKStatus(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"not_found"}`))
	}))
	defer ts.Close()

	c, err := fapihttp.New(ts.Client(), validLoopbackConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = c.Post(context.Background(), fapihttp.PostRequest{
		URL: mustParseURL(t, ts.URL), Body: []byte("x=1"),
		ContentType: "application/x-www-form-urlencoded", ExpectedContentType: "application/json",
	})
	if !errors.Is(err, fapihttp.ErrUnexpectedStatus) {
		t.Fatalf("Post = %v, want ErrUnexpectedStatus", err)
	}
}

// TestPostDoesNotFollowRedirects covers Post's one deliberate difference
// from Fetch — see Post's own doc comment for why resending a POST body
// across a 3xx is out of scope rather than silently mishandled.
func TestPostDoesNotFollowRedirects(t *testing.T) {
	var ts *httptest.Server
	ts = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, ts.URL+"/elsewhere", http.StatusFound)
	}))
	defer ts.Close()

	c, err := fapihttp.New(noRedirectClient(ts), validLoopbackConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = c.Post(context.Background(), fapihttp.PostRequest{
		URL: mustParseURL(t, ts.URL), Body: []byte("x=1"),
		ContentType: "application/x-www-form-urlencoded", ExpectedContentType: "application/json",
	})
	if !errors.Is(err, fapihttp.ErrUnexpectedStatus) {
		t.Fatalf("Post(redirect response) = %v, want ErrUnexpectedStatus", err)
	}
}

// TestPostRejectsInsecureURL confirms Post reuses the same URL
// validation Fetch does — not an exhaustive re-verification of every
// SSRF/scheme rule, which Fetch's own test suite already covers for the
// shared validateFetchURL/checkHostIPs code.
func TestPostRejectsInsecureURL(t *testing.T) {
	c, err := fapihttp.New(http.DefaultClient, validConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = c.Post(context.Background(), fapihttp.PostRequest{
		URL: mustParseURL(t, "http://example.org"), Body: []byte("x=1"),
		ContentType: "application/x-www-form-urlencoded", ExpectedContentType: "application/json",
	})
	if !errors.Is(err, fapihttp.ErrInsecureURL) {
		t.Fatalf("Post(http URL) = %v, want ErrInsecureURL", err)
	}
}

func TestPostRejectsMissingTLSState(t *testing.T) {
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
	_, err = c.Post(context.Background(), fapihttp.PostRequest{
		URL: mustParseURL(t, "https://1.1.1.1/status"), Body: []byte("x=1"),
		ContentType: "application/x-www-form-urlencoded", ExpectedContentType: "application/json",
	})
	if err == nil {
		t.Fatalf("Post(no TLS state) = nil error, want error")
	}
}

package fapihttp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/idfoundry/fapigo/fapihttp"
)

// acceptRecorder is a TLS server that records the Accept header of
// every request, redirecting /a to /b and answering /b with a signed
// metadata document.
func acceptRecorder(t *testing.T) (*httptest.Server, func() map[string]string) {
	t.Helper()
	var mu sync.Mutex
	seen := map[string]string{}
	var ts *httptest.Server
	ts = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.Method+" "+r.URL.Path] = r.Header.Get("Accept")
		_, sent := r.Header["Accept"]
		if !sent {
			seen[r.Method+" "+r.URL.Path] = "<none>"
		}
		mu.Unlock()
		if r.URL.Path == "/a" {
			http.Redirect(w, r, ts.URL+"/b", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/jwt")
		_, _ = w.Write([]byte("a.b.c"))
	}))
	t.Cleanup(ts.Close)
	return ts, func() map[string]string {
		mu.Lock()
		defer mu.Unlock()
		out := map[string]string{}
		for k, v := range seen {
			out[k] = v
		}
		return out
	}
}

// TestFetchSendsAcceptOnEveryHop: FetchRequest.Accept is sent on the
// first request and again on the redirect hop Fetch follows.
func TestFetchSendsAcceptOnEveryHop(t *testing.T) {
	ts, seen := acceptRecorder(t)
	c, err := fapihttp.New(noRedirectClient(ts), validLoopbackConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.Fetch(context.Background(), fapihttp.FetchRequest{
		URL:                   mustParseURL(t, ts.URL+"/a"),
		Accept:                "application/jwt",
		ExpectedContentType:   "application/jwt",
		AlternateContentTypes: []string{"application/json"},
	}); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	for _, hop := range []string{"GET /a", "GET /b"} {
		if got := seen()[hop]; got != "application/jwt" {
			t.Errorf("%s: Accept = %q, want application/jwt", hop, got)
		}
	}
}

// TestFetchWithoutAcceptSendsNone: with no Accept set, none is sent,
// as before.
func TestFetchWithoutAcceptSendsNone(t *testing.T) {
	ts, seen := acceptRecorder(t)
	c, err := fapihttp.New(noRedirectClient(ts), validLoopbackConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.Fetch(context.Background(), fapihttp.FetchRequest{
		URL:                 mustParseURL(t, ts.URL+"/b"),
		ExpectedContentType: "application/jwt",
	}); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got := seen()["GET /b"]; got != "<none>" {
		t.Errorf("Accept = %q, want no Accept header", got)
	}
}

// TestPostSendsAccept: PostRequest.Accept is sent too.
func TestPostSendsAccept(t *testing.T) {
	ts, seen := acceptRecorder(t)
	c, err := fapihttp.New(noRedirectClient(ts), validLoopbackConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.Post(context.Background(), fapihttp.PostRequest{
		URL:                 mustParseURL(t, ts.URL+"/b"),
		Body:                []byte("x=1"),
		ContentType:         "application/x-www-form-urlencoded",
		Accept:              "application/jwt",
		ExpectedContentType: "application/jwt",
	}); err != nil {
		t.Fatalf("Post: %v", err)
	}
	if got := seen()["POST /b"]; got != "application/jwt" {
		t.Errorf("Accept = %q, want application/jwt", got)
	}
}

// TestFetchAndPostRefuseAnInvalidAccept: an Accept with a control
// character, a non-ASCII byte, or over 1024 bytes is refused before any
// request is sent.
func TestFetchAndPostRefuseAnInvalidAccept(t *testing.T) {
	ts, seen := acceptRecorder(t)
	c, err := fapihttp.New(noRedirectClient(ts), validLoopbackConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for name, accept := range map[string]string{
		"CRLF":      "application/jwt\r\nX-Injected: 1",
		"tab":       "application/jwt\tq=1",
		"DEL":       "application/jwt\x7f",
		"non-ASCII": "application/jwt; é",
		"too long":  strings.Repeat("a", 1025),
	} {
		t.Run(name, func(t *testing.T) {
			// Refused by Fetch and Post themselves, not left to net/http.
			if _, err := c.Fetch(context.Background(), fapihttp.FetchRequest{
				URL: mustParseURL(t, ts.URL+"/b"), Accept: accept, ExpectedContentType: "application/jwt",
			}); err == nil || !strings.Contains(err.Error(), "fapihttp: accept") {
				t.Errorf("Fetch = %v, want the accept refusal", err)
			}
			if _, err := c.Post(context.Background(), fapihttp.PostRequest{
				URL: mustParseURL(t, ts.URL+"/b"), Body: []byte("x"), ContentType: "text/plain",
				Accept: accept, ExpectedContentType: "application/jwt",
			}); err == nil || !strings.Contains(err.Error(), "fapihttp: accept") {
				t.Errorf("Post = %v, want the accept refusal", err)
			}
		})
	}
	if n := len(seen()); n != 0 {
		t.Errorf("server saw %d requests, want none", n)
	}
	// The longest allowed value is accepted.
	if _, err := c.Fetch(context.Background(), fapihttp.FetchRequest{
		URL: mustParseURL(t, ts.URL+"/b"), Accept: strings.Repeat("a", 1024), ExpectedContentType: "application/jwt",
	}); err != nil {
		t.Errorf("Fetch with a 1024-byte Accept: %v", err)
	}
}

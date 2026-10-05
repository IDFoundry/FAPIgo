package fapihttp_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/idfoundry/fapigo/fapihttp"
)

// redirectServer answers "/" with a same-origin redirect of status to
// "/elsewhere", which answers 200 JSON and counts its hits.
func redirectServer(t *testing.T, status int) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/elsewhere", status)
	})
	mux.HandleFunc("/elsewhere", func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{}`)
	})
	ts := httptest.NewTLSServer(mux)
	t.Cleanup(ts.Close)
	return ts, &hits
}

// A plain *http.Client follows redirects by default; New's copy must
// not, so Post's "never follows a redirect" holds without the caller
// configuring anything.
func TestPostWithPlainHTTPClientDoesNotFollowRedirect(t *testing.T) {
	ts, hits := redirectServer(t, http.StatusTemporaryRedirect)
	plain := ts.Client()

	c, err := fapihttp.New(plain, validLoopbackConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = c.Post(context.Background(), fapihttp.PostRequest{
		URL: mustParseURL(t, ts.URL), Body: []byte("secret=1"),
		ContentType: "application/x-www-form-urlencoded", ExpectedContentType: "application/json",
	})
	if !errors.Is(err, fapihttp.ErrUnexpectedStatus) {
		t.Fatalf("Post(307) = %v, want ErrUnexpectedStatus", err)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("redirect target was hit %d times, want 0", n)
	}
	if plain.CheckRedirect != nil {
		t.Fatal("New modified the caller's own http.Client")
	}
}

// With MaxRedirects zero, Fetch must refuse the redirect itself rather
// than a plain *http.Client following it first.
func TestFetchWithPlainHTTPClientHonoursMaxRedirects(t *testing.T) {
	ts, hits := redirectServer(t, http.StatusFound)
	cfg := validLoopbackConfig()
	cfg.MaxRedirects = 0

	c, err := fapihttp.New(ts.Client(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = c.Fetch(context.Background(), fapihttp.FetchRequest{
		URL: mustParseURL(t, ts.URL), ExpectedContentType: "application/json",
	})
	if !errors.Is(err, fapihttp.ErrTooManyRedirects) {
		t.Fatalf("Fetch = %v, want ErrTooManyRedirects", err)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("redirect target was hit %d times, want 0", n)
	}
}

// followingClient is an HTTPClient that isn't an *http.Client and
// reports a response to a different URL than the one requested, as one
// that followed a redirect itself does.
type followingClient struct{}

func (followingClient) Do(req *http.Request) (*http.Response, error) {
	hop := req.Clone(req.Context())
	hop.URL.Path = "/elsewhere"
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{}`)),
		Request:    hop,
	}, nil
}

func TestFetchAndPostRefuseAClientThatFollowedARedirect(t *testing.T) {
	c, err := fapihttp.New(followingClient{}, validConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	target := mustParseURL(t, "https://1.1.1.1/jwks") // IP literal: no DNS
	_, err = c.Fetch(context.Background(), fapihttp.FetchRequest{URL: target, ExpectedContentType: "application/json"})
	if !errors.Is(err, fapihttp.ErrRedirectFollowed) {
		t.Fatalf("Fetch = %v, want ErrRedirectFollowed", err)
	}
	_, err = c.Post(context.Background(), fapihttp.PostRequest{
		URL: target, Body: []byte("x=1"),
		ContentType: "application/x-www-form-urlencoded", ExpectedContentType: "application/json",
	})
	if !errors.Is(err, fapihttp.ErrRedirectFollowed) {
		t.Fatalf("Post = %v, want ErrRedirectFollowed", err)
	}
}

// wrappedClient is a metrics or tracing HTTPClient around an
// *http.Client that follows redirects: New can't stop it following one.
type wrappedClient struct{ c *http.Client }

func (w wrappedClient) Do(req *http.Request) (*http.Response, error) { return w.c.Do(req) }

// Post's body isn't resent across a 307 or 308 even through a wrapper
// New couldn't make non-following.
func TestPostBodyIsNotResentThroughAWrappingHTTPClient(t *testing.T) {
	for _, status := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			ts, hits := redirectServer(t, status)
			c, err := fapihttp.New(wrappedClient{c: ts.Client()}, validLoopbackConfig())
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			_, err = c.Post(context.Background(), fapihttp.PostRequest{
				URL: mustParseURL(t, ts.URL), Body: []byte("secret=1"),
				ContentType: "application/x-www-form-urlencoded", ExpectedContentType: "application/json",
			})
			if err == nil || !strings.Contains(err.Error(), "never resent") {
				t.Fatalf("Post(%d) = %v, want the body-not-resent refusal", status, err)
			}
			if n := hits.Load(); n != 0 {
				t.Fatalf("redirect target was hit %d times, want 0", n)
			}
		})
	}
}

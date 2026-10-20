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

// TestFetchAndPostSendAcceptLanguageAndReturnHeaders: AcceptLanguage is
// sent on every hop and on a POST; the response's headers come back in
// FetchResponse.Header (the final response's, after a redirect), as a
// copy.
func TestFetchAndPostSendAcceptLanguageAndReturnHeaders(t *testing.T) {
	var mu sync.Mutex
	languages := map[string]string{}
	var ts *httptest.Server
	ts = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		languages[r.Method+" "+r.URL.Path] = r.Header.Get("Accept-Language")
		mu.Unlock()
		if r.URL.Path == "/a" {
			w.Header().Set("DPoP-Nonce", "from-the-redirect")
			http.Redirect(w, r, ts.URL+"/b", http.StatusFound)
			return
		}
		w.Header().Set("DPoP-Nonce", "nonce-1")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer ts.Close()
	c, err := fapihttp.New(noRedirectClient(ts), validLoopbackConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()

	res, err := c.Fetch(ctx, fapihttp.FetchRequest{
		URL: mustParseURL(t, ts.URL+"/a"), AcceptLanguage: "de-CH, en;q=0.5", ExpectedContentType: "application/json",
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got := res.Header.Get("DPoP-Nonce"); got != "nonce-1" {
		t.Errorf("Fetch Header DPoP-Nonce = %q, want the final response's nonce-1", got)
	}
	res.Header.Set("DPoP-Nonce", "changed")

	posted, err := c.Post(ctx, fapihttp.PostRequest{
		URL: mustParseURL(t, ts.URL+"/b"), Body: []byte("x=1"), ContentType: "application/x-www-form-urlencoded",
		AcceptLanguage: "fr", ExpectedContentType: "application/json",
	})
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	if got := posted.Header.Get("DPoP-Nonce"); got != "nonce-1" {
		t.Errorf("Post Header DPoP-Nonce = %q, want nonce-1", got)
	}

	mu.Lock()
	defer mu.Unlock()
	for hop, want := range map[string]string{"GET /a": "de-CH, en;q=0.5", "GET /b": "de-CH, en;q=0.5", "POST /b": "fr"} {
		if languages[hop] != want {
			t.Errorf("%s: Accept-Language = %q, want %q", hop, languages[hop], want)
		}
	}
}

// TestFetchAndPostRefuseAnInvalidAcceptLanguage: AcceptLanguage follows
// Accept's rules, so a line break can't smuggle another header in.
func TestFetchAndPostRefuseAnInvalidAcceptLanguage(t *testing.T) {
	c, err := fapihttp.New(http.DefaultClient, validLoopbackConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, value := range []string{"en\r\nCookie: x", strings.Repeat("a", 1025)} {
		if _, err := c.Fetch(context.Background(), fapihttp.FetchRequest{
			URL: mustParseURL(t, "https://127.0.0.1/x"), AcceptLanguage: value, ExpectedContentType: "application/json",
		}); err == nil || !strings.Contains(err.Error(), "accept-language") {
			t.Errorf("Fetch(AcceptLanguage %q) = %v, want refused", value, err)
		}
		if _, err := c.Post(context.Background(), fapihttp.PostRequest{
			URL: mustParseURL(t, "https://127.0.0.1/x"), ContentType: "text/plain", AcceptLanguage: value, ExpectedContentType: "application/json",
		}); err == nil || !strings.Contains(err.Error(), "accept-language") {
			t.Errorf("Post(AcceptLanguage %q) = %v, want refused", value, err)
		}
	}
}

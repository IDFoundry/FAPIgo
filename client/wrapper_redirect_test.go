package client_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/internal/nofollow"
	"github.com/idfoundry/fapigo/storage"
)

// instrumented is the shape of a metrics or tracing HTTPClient: it
// wraps an *http.Client that follows redirects by default, and isn't
// itself an *http.Client, so New can't stop it following one.
type instrumented struct{ c *http.Client }

func (i instrumented) Do(req *http.Request) (*http.Response, error) { return i.c.Do(req) }

// collector is another origin a redirect points at; it records every
// request and body that reach it.
type collector struct {
	hits  atomic.Int32
	bytes atomic.Int64
}

func newCollector(t *testing.T) (*collector, *httptest.Server) {
	t.Helper()
	col := &collector{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		col.hits.Add(1)
		n, _ := io.Copy(io.Discard, r.Body)
		col.bytes.Add(n)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(ts.Close)
	return col, ts
}

// redirectTo answers every request with status to target.
func redirectTo(t *testing.T, target string, status int) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		http.Redirect(w, r, target, status)
	}))
	t.Cleanup(ts.Close)
	return ts
}

// A token endpoint answering 307/308 to another origin must not get the
// token request (and its client assertion) resent there, even through
// an HTTPClient New couldn't make non-following.
func TestTokenRequestBodyIsNotResentThroughAWrappingHTTPClient(t *testing.T) {
	for _, status := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			col, target := newCollector(t)
			as := redirectTo(t, target.URL+"/collect", status)

			cfg := validConfig(t)
			tokenURL, err := fapi.ParseEndpointURL(as.URL+"/token", fapi.AllowLoopbackHTTP())
			if err != nil {
				t.Fatalf("ParseEndpointURL: %v", err)
			}
			cfg.Endpoints.Token = tokenURL
			deps := validDependencies(t)
			deps.HTTP = instrumented{c: &http.Client{}}
			c, err := client.New(cfg, deps)
			if err != nil {
				t.Fatalf("client.New: %v", err)
			}
			_, err = c.RequestClientCredentialsToken(context.Background(), client.ClientCredentialsTokenRequest{Scope: []string{"accounts"}})
			if !errors.Is(err, nofollow.ErrBodyNotResent) {
				t.Fatalf("RequestClientCredentialsToken(%d) = %v, want ErrBodyNotResent", status, err)
			}
			if n, b := col.hits.Load(), col.bytes.Load(); n != 0 || b != 0 {
				t.Fatalf("redirect target received %d request(s), %d body bytes; want none", n, b)
			}
		})
	}
}

// A protected resource POST through a wrapping HTTPClient isn't resent
// across a 307 either, while the caller's own GetBody keeps serving the
// client's DPoP nonce retry.
func TestProtectedResourceBodyIsNotResentThroughAWrappingHTTPClient(t *testing.T) {
	for _, sc := range []storage.SenderConstrain{storage.SenderConstrainDPoP, storage.SenderConstrainMTLS} {
		t.Run(string(sc), func(t *testing.T) {
			col, target := newCollector(t)
			rs := redirectTo(t, target.URL+"/collect", http.StatusTemporaryRedirect)

			cfg := validConfig(t)
			cfg.SenderConstrain = sc
			deps := validDependencies(t)
			deps.HTTP = instrumented{c: &http.Client{}}
			c, err := client.New(cfg, deps)
			if err != nil {
				t.Fatalf("client.New: %v", err)
			}
			rc := c.ProtectedResource(client.TokenSet{AccessToken: fapi.NewSecret("test-access-token")})
			req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, rs.URL+"/payments", strings.NewReader(`{"amount":"1"}`))
			if err != nil {
				t.Fatalf("NewRequestWithContext: %v", err)
			}
			if _, err := rc.Do(context.Background(), req); !errors.Is(err, nofollow.ErrBodyNotResent) {
				t.Fatalf("Do(307) = %v, want ErrBodyNotResent", err)
			}
			if req.GetBody == nil {
				t.Fatal("Do cleared the caller's own GetBody")
			}
			if n, b := col.hits.Load(), col.bytes.Load(); n != 0 || b != 0 {
				t.Fatalf("redirect target received %d request(s), %d body bytes; want none", n, b)
			}
		})
	}
}

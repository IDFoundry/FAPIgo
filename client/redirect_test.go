package client_test

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/storage"
)

// redirectingResource answers every path but "/elsewhere" with a 307 to
// "/elsewhere", and records the Authorization and DPoP headers that
// reach "/elsewhere".
type redirectingResource struct {
	hits      atomic.Int32
	leakedTok atomic.Value
}

func (rr *redirectingResource) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/elsewhere" {
			rr.hits.Add(1)
			rr.leakedTok.Store(r.Header.Get("Authorization") + "|" + r.Header.Get("DPoP"))
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, "/elsewhere", http.StatusTemporaryRedirect)
	})
}

// A plain *http.Client follows redirects by default and, within the
// same host, forwards the Authorization and DPoP headers; Do must
// return the redirect instead, under DPoP and under mTLS.
func TestProtectedResourceDoDoesNotFollowRedirect(t *testing.T) {
	for name, mutate := range map[string]func(*client.Config){
		"dpop": nil,
		"mtls": func(cfg *client.Config) {
			cfg.SenderConstrain = storage.SenderConstrainMTLS
			cfg.Algorithms.DPoP = 0
		},
	} {
		t.Run(name, func(t *testing.T) {
			rr := &redirectingResource{}
			ts := httptest.NewServer(rr.handler())
			defer ts.Close()

			c := newResourceTestClient(t, ts, mutate)
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/resource", nil)
			res, err := c.ProtectedResource(client.TokenSet{AccessToken: fapi.NewSecret("test-access-token")}).Do(context.Background(), req)
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			_ = res.Body.Close()
			if res.StatusCode != http.StatusTemporaryRedirect {
				t.Fatalf("status = %d, want the 307 itself", res.StatusCode)
			}
			if n := rr.hits.Load(); n != 0 {
				t.Fatalf("redirect target received the token %d times (%v), want 0", n, rr.leakedTok.Load())
			}
		})
	}
}

func TestProtectedResourceDoRefusesURL(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	c := newResourceTestClient(t, ts, nil)
	rc := c.ProtectedResource(client.TokenSet{AccessToken: fapi.NewSecret("test-access-token")})

	for name, raw := range map[string]string{
		"http to a non-loopback host": "http://resource.example.com/accounts",
		"embedded credentials":        "https://user:pass@resource.example.com/accounts",
		"other scheme":                "ftp://resource.example.com/accounts",
	} {
		t.Run(name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, raw, nil)
			if err != nil {
				t.Fatalf("NewRequestWithContext: %v", err)
			}
			_, err = rc.Do(context.Background(), req)
			var cerr *client.Error
			if !errors.As(err, &cerr) || cerr.Code() != client.ErrorInvalidRequest {
				t.Fatalf("Do(%s) = %v, want invalid_request", raw, err)
			}
		})
	}
	t.Run("missing URL", func(t *testing.T) {
		_, err := rc.Do(context.Background(), &http.Request{Method: http.MethodGet, Header: http.Header{}})
		var cerr *client.Error
		if !errors.As(err, &cerr) || cerr.Code() != client.ErrorInvalidRequest {
			t.Fatalf("Do(no URL) = %v, want invalid_request", err)
		}
	})
}

// fakeResourceHTTP returns one canned response, with Request set to
// req or, when follow is set, a clone of req at another path — what an
// HTTPClient that followed a redirect itself returns.
type fakeResourceHTTP struct {
	follow bool
	tls    bool
}

func (f fakeResourceHTTP) Do(req *http.Request) (*http.Response, error) {
	answered := req
	if f.follow {
		answered = req.Clone(req.Context())
		answered.URL.Path = "/elsewhere"
	}
	res := &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("ok")), Request: answered}
	if f.tls {
		res.TLS = &tls.ConnectionState{HandshakeComplete: true}
	}
	return res, nil
}

func TestProtectedResourceDoRefusesUnsafeResponses(t *testing.T) {
	cases := map[string]struct {
		http fakeResourceHTTP
		want error
	}{
		"client followed a redirect itself": {fakeResourceHTTP{follow: true, tls: true}, fapihttp.ErrRedirectFollowed},
		"https response without TLS":        {fakeResourceHTTP{}, fapihttp.ErrMissingTLS},
	}
	for name, tc := range cases {
		for mode, mutate := range map[string]func(*client.Config){
			"dpop": nil,
			"mtls": func(cfg *client.Config) {
				cfg.SenderConstrain = storage.SenderConstrainMTLS
				cfg.Algorithms.DPoP = 0
			},
		} {
			t.Run(name+"/"+mode, func(t *testing.T) {
				cfg := validConfig(t)
				if mutate != nil {
					mutate(&cfg)
				}
				deps := validDependencies(t)
				deps.HTTP = tc.http
				c, err := client.New(cfg, deps)
				if err != nil {
					t.Fatalf("client.New: %v", err)
				}
				req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://resource.example.com/accounts", nil)
				_, err = c.ProtectedResource(client.TokenSet{AccessToken: fapi.NewSecret("test-access-token")}).Do(context.Background(), req)
				if !errors.Is(err, tc.want) {
					t.Fatalf("Do = %v, want %v", err, tc.want)
				}
			})
		}
	}
	t.Run("https response over TLS is returned", func(t *testing.T) {
		deps := validDependencies(t)
		deps.HTTP = fakeResourceHTTP{tls: true}
		c, err := client.New(validConfig(t), deps)
		if err != nil {
			t.Fatalf("client.New: %v", err)
		}
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://resource.example.com/accounts", nil)
		res, err := c.ProtectedResource(client.TokenSet{AccessToken: fapi.NewSecret("test-access-token")}).Do(context.Background(), req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		_ = res.Body.Close()
	})
}

// The token endpoint's POST carries the client's authentication; a
// plain *http.Client must not resend it across a 307.
func TestTokenRequestDoesNotFollowRedirect(t *testing.T) {
	var hits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/elsewhere" {
			hits.Add(1)
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, "/elsewhere", http.StatusTemporaryRedirect)
	}))
	defer ts.Close()

	cfg := validConfig(t)
	tokenURL, err := fapi.ParseEndpointURL(ts.URL+"/token", fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	cfg.Endpoints.Token = tokenURL
	deps := validDependencies(t)
	deps.HTTP = ts.Client()
	c, err := client.New(cfg, deps)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	if _, err := c.RequestClientCredentialsToken(context.Background(), client.ClientCredentialsTokenRequest{Scope: []string{"accounts"}}); err == nil {
		t.Fatal("RequestClientCredentialsToken(307) = nil error, want an error")
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("redirect target received the token request %d times, want 0", n)
	}
}

func TestTokenRequestRefusesAClientThatFollowedARedirect(t *testing.T) {
	cfg := validConfig(t)
	tokenURL, err := fapi.ParseEndpointURL("https://as.example.com/token")
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	cfg.Endpoints.Token = tokenURL
	deps := validDependencies(t)
	deps.HTTP = fakeResourceHTTP{follow: true, tls: true}
	c, err := client.New(cfg, deps)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	_, err = c.RequestClientCredentialsToken(context.Background(), client.ClientCredentialsTokenRequest{Scope: []string{"accounts"}})
	if !errors.Is(err, fapihttp.ErrRedirectFollowed) {
		t.Fatalf("RequestClientCredentialsToken = %v, want ErrRedirectFollowed", err)
	}
}

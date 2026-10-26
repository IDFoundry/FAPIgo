package client_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/storage"
)

// TestProtectedResourceDoRefusesAPathItsProofWouldNormalize: the proof's
// htu names the normalized path, but the request goes out with the path
// as written, so a front end routing by raw path delivers
// /rs-a/%2e%2e/rs-b/x to RS-A with a proof RS-B would accept. Under DPoP
// Do refuses such a URL, sending nothing; a normal one, with an encoded
// reserved character, a trailing slash or a query string, goes out with
// an htu naming the path it was sent to.
func TestProtectedResourceDoRefusesAPathItsProofWouldNormalize(t *testing.T) {
	var (
		mu    sync.Mutex
		paths []string
		htus  []any
	)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.EscapedPath())
		htus = append(htus, dpopProofClaims(t, r.Header.Get("DPoP"))["htu"])
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	c := newResourceTestClient(t, ts, nil)
	rc := c.ProtectedResource(client.TokenSet{AccessToken: fapi.NewSecret("at")})
	do := func(path string) error {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		res, err := rc.Do(context.Background(), req)
		if err == nil {
			_ = res.Body.Close()
		}
		return err
	}

	for _, path := range []string{"/rs-a/%2e%2e/rs-b/payments", "/rs-a/../rs-b/payments", "/rs-a/./x", "/rs-b/%70ayments"} {
		var cerr *client.Error
		if err := do(path); !errors.As(err, &cerr) || cerr.Code() != client.ErrorInvalidRequest {
			t.Errorf("Do(%s) = %v, want ErrorInvalidRequest", path, err)
		}
	}
	mu.Lock()
	if len(paths) != 0 {
		t.Fatalf("the resource server received %v", paths)
	}
	mu.Unlock()

	for _, path := range []string{"/rs-b/a%2Fb", "/rs-b/dir/", "/rs-b/x?next=../y"} {
		if err := do(path); err != nil {
			t.Errorf("Do(%s) = %v", path, err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	for i, want := range []string{"/rs-b/a%2Fb", "/rs-b/dir/", "/rs-b/x"} {
		if i >= len(paths) || paths[i] != want || htus[i] != ts.URL+want {
			t.Errorf("request %d: path %v, htu %v; want path %s and htu %s", i, paths, htus, want, ts.URL+want)
		}
	}
}

// TestProtectedResourceDoMTLSAllowsAnyPath: under SenderConstrainMTLS no
// proof names the path, so Do sends it as written.
func TestProtectedResourceDoMTLSAllowsAnyPath(t *testing.T) {
	var got string
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.EscapedPath()
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	c := newResourceTestClient(t, ts, func(cfg *client.Config) { cfg.SenderConstrain = storage.SenderConstrainMTLS })
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/a/%2e%2e/b", nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.ProtectedResource(client.TokenSet{AccessToken: fapi.NewSecret("at")}).Do(context.Background(), req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_ = res.Body.Close()
	if got != "/a/%2e%2e/b" {
		t.Errorf("path = %q", got)
	}
}

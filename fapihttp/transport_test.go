package fapihttp_test

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/fapihttp"
)

func validTransportConfig() fapihttp.TransportConfig {
	return fapihttp.TransportConfig{
		DialTimeout:         2 * time.Second,
		TLSHandshakeTimeout: 2 * time.Second,
	}
}

func TestNewClientRejectsInvalidConfig(t *testing.T) {
	cases := map[string]func(*fapihttp.TransportConfig){
		"zero dial timeout":          func(c *fapihttp.TransportConfig) { c.DialTimeout = 0 },
		"zero tls handshake timeout": func(c *fapihttp.TransportConfig) { c.TLSHandshakeTimeout = 0 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := validTransportConfig()
			mutate(&cfg)
			if _, err := fapihttp.NewClient(cfg); err == nil {
				t.Fatalf("NewClient(%s) = nil error, want error", name)
			}
		})
	}
}

func TestNewClientDoesNotFollowRedirectsItself(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/somewhere-else", http.StatusFound)
	}))
	defer ts.Close()

	cfg := validTransportConfig()
	cfg.AllowLoopbackHTTP = true
	client, err := fapihttp.NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusFound {
		t.Errorf("StatusCode = %d, want %d (redirect returned, not followed)", res.StatusCode, http.StatusFound)
	}
}

func TestNewClientBlocksLoopbackByDefault(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer ts.Close()

	client, err := fapihttp.NewClient(validTransportConfig())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if _, err := client.Do(req); err == nil {
		t.Fatalf("Do(loopback, AllowLoopbackHTTP=false) = nil error, want error")
	}
}

func TestNewClientAllowsLoopbackWhenConfigured(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer ts.Close()

	cfg := validTransportConfig()
	cfg.AllowLoopbackHTTP = true
	client, err := fapihttp.NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do(loopback, AllowLoopbackHTTP=true): %v", err)
	}
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", res.StatusCode)
	}
}

// TestNewClientLoopbackHostsDialsLoopbackLiteral covers the https-only
// development setting at dial time: AllowLoopbackHosts alone lets the
// transport dial a literal loopback address.
func TestNewClientLoopbackHostsDialsLoopbackLiteral(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer ts.Close()

	cfg := validTransportConfig()
	cfg.AllowLoopbackHosts = true
	client, err := fapihttp.NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do(loopback literal, AllowLoopbackHosts=true): %v", err)
	}
	res.Body.Close()
}

// TestNewClientVerifyConnection: the hook sees each handshake's verified
// chains, and its error fails the request.
func TestNewClientVerifyConnection(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer ts.Close()

	refuse := errors.New("pin mismatch")
	for name, tc := range map[string]struct {
		hookErr error
		wantErr bool
	}{
		"accepts": {nil, false},
		"refuses": {refuse, true},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := validTransportConfig()
			cfg.AllowLoopbackHosts = true
			var calls, chains int
			cfg.VerifyConnection = func(cs tls.ConnectionState) error {
				calls++
				chains = len(cs.VerifiedChains)
				return tc.hookErr
			}
			client, err := fapihttp.NewClient(cfg)
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			client.Transport.(*http.Transport).TLSClientConfig.RootCAs = ts.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs

			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL, nil)
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			res, err := client.Do(req)
			if res != nil {
				res.Body.Close()
			}
			if tc.wantErr != (err != nil) || (tc.wantErr && !errors.Is(err, refuse)) {
				t.Fatalf("Do = %v, want error %v", err, tc.hookErr)
			}
			if calls != 1 || chains == 0 {
				t.Errorf("hook ran %d times with %d verified chains, want once with some", calls, chains)
			}
		})
	}
}

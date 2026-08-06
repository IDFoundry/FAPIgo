package fapihttp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/osanderson/go-fapi/fapihttp"
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

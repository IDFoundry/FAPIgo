package fapihttp

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

// TestNewClientCopiesHostLists: changing the AllowedPrivateHosts slice
// passed to NewClient afterwards neither widens what the dialer allows
// nor makes it disagree with what HardeningOf reports.
func TestNewClientCopiesHostLists(t *testing.T) {
	cfg := RecommendedTransportConfig()
	cfg.DialTimeout = 200 * time.Millisecond
	cfg.AllowedPrivateHosts = []string{"jwks.internal.example"}
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.AllowedPrivateHosts[0] = "10.255.255.1"
	_, err = c.Transport.(*http.Transport).DialContext(context.Background(), "tcp", "10.255.255.1:9")
	if !errors.Is(err, ErrSSRFBlocked) {
		t.Fatalf("dial after changing the caller's slice = %v, want ErrSSRFBlocked", err)
	}
	h, ok := HardeningOf(c)
	if !ok || len(h.AllowedPrivateHosts()) != 1 || h.AllowedPrivateHosts()[0] != "jwks.internal.example" {
		t.Fatalf("HardeningOf = %v, %v; want the original list", h.AllowedPrivateHosts(), ok)
	}
}

// TestNewCopiesHostLists: New keeps its own copy of Config's host lists.
func TestNewCopiesHostLists(t *testing.T) {
	cfg := RecommendedConfig()
	cfg.AllowedPrivateHosts = []string{"jwks.internal.example"}
	cfg.AllowedLoopbackHosts = []string{"dev.localhost"}
	f, err := New(http.DefaultClient, cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.AllowedPrivateHosts[0] = "10.255.255.1"
	cfg.AllowedLoopbackHosts[0] = "evil.localhost"
	if f.cfg.AllowedPrivateHosts[0] != "jwks.internal.example" || f.cfg.AllowedLoopbackHosts[0] != "dev.localhost" {
		t.Fatalf("New's config followed the caller's slices: %v %v", f.cfg.AllowedPrivateHosts, f.cfg.AllowedLoopbackHosts)
	}
}

package fapihttp

import (
	"context"
	"errors"
	"net"
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

// TestHardeningOfRefusesAnotherTransportsDialer: a dialer taken from a
// NewClient transport built with a loopback exception, swapped into a
// strict one, isn't this transport's dialer, so the strict transport
// stops counting as hardened instead of reporting no loopback exception
// while dialing loopback.
func TestHardeningOfRefusesAnotherTransportsDialer(t *testing.T) {
	strict, err := NewClient(RecommendedTransportConfig())
	if err != nil {
		t.Fatal(err)
	}
	looseCfg := RecommendedTransportConfig()
	looseCfg.AllowLoopbackHosts = true
	loose, err := NewClient(looseCfg)
	if err != nil {
		t.Fatal(err)
	}
	strict.Transport.(*http.Transport).DialContext = loose.Transport.(*http.Transport).DialContext
	if h, ok := HardeningOf(strict); ok {
		t.Fatalf("HardeningOf = %+v, true; want false for another transport's dialer", h)
	}
	if h, ok := HardeningOf(loose); !ok || !h.AllowsLoopback() {
		t.Fatalf("HardeningOf(loose) = %+v, %v; want its own dialer still recognised", h, ok)
	}
}

// TestHardeningOfNeverCallsAForeignDialer: HardeningOf probes only a
// closure NewClient built; any other DialContext is refused without
// being called.
func TestHardeningOfNeverCallsAForeignDialer(t *testing.T) {
	c, err := NewClient(RecommendedTransportConfig())
	if err != nil {
		t.Fatal(err)
	}
	called := false
	c.Transport.(*http.Transport).DialContext = func(context.Context, string, string) (net.Conn, error) {
		called = true
		return nil, errors.New("foreign dialer")
	}
	if _, ok := HardeningOf(c); ok {
		t.Fatal("HardeningOf = true for a foreign dialer")
	}
	if called {
		t.Fatal("HardeningOf called a dialer NewClient didn't build")
	}
}

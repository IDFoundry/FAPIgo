package fapihttp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
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

// TestHardeningOfRefusesTLSWeakenings: each change below weakens or
// reveals what the handshake checks, so a transport with it no longer
// counts as hardened.
func TestHardeningOfRefusesTLSWeakenings(t *testing.T) {
	for name, tamper := range map[string]func(*tls.Config){
		"key log":               func(c *tls.Config) { c.KeyLogWriter = io.Discard },
		"fixed clock":           func(c *tls.Config) { c.Time = func() time.Time { return time.Unix(0, 0) } },
		"fixed server name":     func(c *tls.Config) { c.ServerName = "example.com" },
		"insecure cipher suite": func(c *tls.Config) { c.CipherSuites = []uint16{tls.InsecureCipherSuites()[0].ID} },
		"verify peer certificate": func(c *tls.Config) {
			c.VerifyPeerCertificate = func([][]byte, [][]*x509.Certificate) error { return nil }
		},
		"replaced roots":          func(c *tls.Config) { c.RootCAs = x509.NewCertPool() },
		"added verify connection": func(c *tls.Config) { c.VerifyConnection = func(tls.ConnectionState) error { return nil } },
	} {
		t.Run(name, func(t *testing.T) {
			c, err := NewClient(RecommendedTransportConfig())
			if err != nil {
				t.Fatal(err)
			}
			tamper(c.Transport.(*http.Transport).TLSClientConfig)
			if _, ok := HardeningOf(c); ok {
				t.Error("HardeningOf = true, want false")
			}
		})
	}
}

// TestHardeningOfChecksConstructionTLSSettings: RootCAs and
// VerifyConnection set through TransportConfig count as hardened, and
// replacing or removing them afterwards doesn't; neither does another
// NewClient transport's VerifyConnection, and a foreign one is never
// called by the check.
func TestHardeningOfChecksConstructionTLSSettings(t *testing.T) {
	build := func(t *testing.T) *http.Client {
		cfg := RecommendedTransportConfig()
		cfg.RootCAs = x509.NewCertPool()
		cfg.VerifyConnection = func(tls.ConnectionState) error { return nil }
		c, err := NewClient(cfg)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	if _, ok := HardeningOf(build(t)); !ok {
		t.Fatal("HardeningOf = false for RootCAs and VerifyConnection set through TransportConfig")
	}
	other := build(t)
	called := false
	for name, tamper := range map[string]func(*tls.Config){
		"roots replaced":            func(c *tls.Config) { c.RootCAs = x509.NewCertPool() },
		"roots removed":             func(c *tls.Config) { c.RootCAs = nil },
		"verify connection removed": func(c *tls.Config) { c.VerifyConnection = nil },
		"another transport's verify": func(c *tls.Config) {
			c.VerifyConnection = other.Transport.(*http.Transport).TLSClientConfig.VerifyConnection
		},
		"foreign verify connection": func(c *tls.Config) {
			c.VerifyConnection = func(tls.ConnectionState) error { called = true; return nil }
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := build(t)
			tamper(c.Transport.(*http.Transport).TLSClientConfig)
			if _, ok := HardeningOf(c); ok {
				t.Error("HardeningOf = true, want false")
			}
		})
	}
	if called {
		t.Error("HardeningOf called a VerifyConnection NewClient didn't build")
	}
}

// TestNewClientTLSSettingsApplyToHandshakes: RootCAs set through
// TransportConfig is what server certificates are verified against, and
// TransportConfig.VerifyConnection still runs on every handshake.
func TestNewClientTLSSettingsApplyToHandshakes(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer srv.Close()
	cfg := RecommendedTransportConfig()
	cfg.AllowLoopbackHosts = true
	cfg.RootCAs = srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	verified := false
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		verified = len(cs.VerifiedChains) > 0
		return nil
	}
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Get(srv.URL)
	if err != nil {
		t.Fatalf("request with the server's CA as RootCAs: %v", err)
	}
	res.Body.Close()
	if !verified {
		t.Error("TransportConfig.VerifyConnection didn't run on the handshake")
	}
	if _, ok := HardeningOf(c); !ok {
		t.Error("HardeningOf = false after a request")
	}
}

// foreignRoundTripper is a RoundTripper registered for a scheme to send
// requests around the dialer; it records whether it ever ran.
type foreignRoundTripper struct{ used *bool }

func (f foreignRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	*f.used = true
	return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
}

// assertSchemesReserved checks that registering a RoundTripper for
// "https" or "http" on c's transport panics, so nothing can send its
// requests around the address-validating dialer.
func assertSchemesReserved(t *testing.T, c *http.Client) {
	t.Helper()
	for _, scheme := range []string{"https", "http"} {
		used := false
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("RegisterProtocol(%q) didn't panic on a NewClient transport", scheme)
				}
			}()
			c.Transport.(*http.Transport).RegisterProtocol(scheme, foreignRoundTripper{&used})
		}()
		if used {
			t.Errorf("a RoundTripper registered for %q ran", scheme)
		}
	}
}

// TestNewClientReservesSchemes: a fresh NewClient transport, used or
// not, refuses another RoundTripper for "https" or "http", which would
// otherwise reach any address while HardeningOf still reported it
// hardened.
func TestNewClientReservesSchemes(t *testing.T) {
	c, err := NewClient(RecommendedTransportConfig())
	if err != nil {
		t.Fatal(err)
	}
	assertSchemesReserved(t, c)
	if _, ok := HardeningOf(c); !ok {
		t.Error("HardeningOf = false for an untouched NewClient transport")
	}
}

// TestNewClientStillSpeaksHTTP2: reserving the schemes leaves net/http's
// own HTTP/2 support in place.
func TestNewClientStillSpeaksHTTP2(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	cfg := RecommendedTransportConfig()
	cfg.AllowLoopbackHosts = true
	cfg.RootCAs = srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.ProtoMajor != 2 {
		t.Errorf("response protocol = %s, want HTTP/2", res.Proto)
	}
}

// TestNewClientReservesSchemesWithoutHTTP2 runs
// TestNewClientWithoutHTTP2Child with GODEBUG=http2client=0, where
// net/http registers nothing for "https" itself, so reserveSchemes'
// own registration is what refuses another RoundTripper.
func TestNewClientReservesSchemesWithoutHTTP2(t *testing.T) {
	if os.Getenv("FAPIHTTP_HTTP2_OFF_CHILD") == "1" {
		t.Skip("running as the child")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestNewClientWithoutHTTP2Child$", "-test.v")
	cmd.Env = append(os.Environ(), "FAPIHTTP_HTTP2_OFF_CHILD=1", "GODEBUG=http2client=0")
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "--- PASS: TestNewClientWithoutHTTP2Child") {
		t.Fatalf("child with GODEBUG=http2client=0: %v\n%s", err, out)
	}
}

// TestNewClientWithoutHTTP2Child is TestNewClientReservesSchemesWithoutHTTP2's
// child: with HTTP/2 off, the schemes are still reserved, and requests
// still go out over HTTP/1.1 through the transport itself.
func TestNewClientWithoutHTTP2Child(t *testing.T) {
	if os.Getenv("FAPIHTTP_HTTP2_OFF_CHILD") != "1" {
		t.Skip("only runs as TestNewClientReservesSchemesWithoutHTTP2's child")
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer srv.Close()
	cfg := RecommendedTransportConfig()
	cfg.AllowLoopbackHosts = true
	cfg.RootCAs = srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Get(srv.URL)
	if err != nil {
		t.Fatalf("request over HTTP/1.1: %v", err)
	}
	res.Body.Close()
	if res.ProtoMajor != 1 {
		t.Errorf("response protocol = %s, want HTTP/1.1 with HTTP/2 off", res.Proto)
	}
	assertSchemesReserved(t, c)
}

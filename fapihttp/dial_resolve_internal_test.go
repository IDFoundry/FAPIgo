package fapihttp

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// withResolver makes host names resolve to addrs (or fail with err) for
// the rest of the test.
func withResolver(t *testing.T, addrs []string, err error) {
	t.Helper()
	orig := lookupIPAddr
	t.Cleanup(func() { lookupIPAddr = orig })
	lookupIPAddr = func(context.Context, string) ([]net.IPAddr, error) {
		if err != nil {
			return nil, err
		}
		out := make([]net.IPAddr, len(addrs))
		for i, a := range addrs {
			out[i] = net.IPAddr{IP: net.ParseIP(a)}
		}
		return out, nil
	}
}

func testDialer(allowLoopbackHost string) safeDialer {
	d := safeDialer{base: &net.Dialer{Timeout: time.Second}}
	if allowLoopbackHost != "" {
		d.loopback = loopbackPolicy{named: []string{allowLoopbackHost}}
	}
	return d
}

// TestSafeDialerResolvesAndSkipsDisallowedAddresses: a name is resolved
// once, and only the candidates that pass are dialed — a name resolving
// to a link-local address and a permitted loopback one connects to the
// loopback one, and one resolving only to disallowed addresses is
// ErrSSRFBlocked without any dial.
func TestSafeDialerResolvesAndSkipsDisallowedAddresses(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			_ = c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())

	withResolver(t, []string{"169.254.169.254", "127.0.0.1"}, nil)
	conn, err := testDialer("svc.test").dial(context.Background(), "tcp", net.JoinHostPort("svc.test", port))
	if err != nil {
		t.Fatalf("dial = %v, want the permitted loopback candidate", err)
	}
	if got := conn.RemoteAddr().(*net.TCPAddr).IP.String(); got != "127.0.0.1" {
		t.Errorf("dialed %s, want 127.0.0.1", got)
	}
	_ = conn.Close()

	withResolver(t, []string{"10.0.0.1", "169.254.169.254"}, nil)
	if _, err := testDialer("").dial(context.Background(), "tcp", "internal.test:443"); !errors.Is(err, ErrSSRFBlocked) {
		t.Errorf("dial = %v, want ErrSSRFBlocked", err)
	}
}

// TestSafeDialerReportsResolutionAndDialErrors: a resolver failure, a
// malformed address and a refused connection to a permitted address are
// each reported as themselves, not as ErrSSRFBlocked.
func TestSafeDialerReportsResolutionAndDialErrors(t *testing.T) {
	resolveErr := errors.New("no such host")
	withResolver(t, nil, resolveErr)
	if _, err := testDialer("").dial(context.Background(), "tcp", "missing.test:443"); !errors.Is(err, resolveErr) {
		t.Errorf("dial = %v, want the resolver's error", err)
	}

	if _, err := testDialer("").dial(context.Background(), "tcp", "no-port"); err == nil || errors.Is(err, ErrSSRFBlocked) {
		t.Errorf("dial(no port) = %v, want an address error", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close() // nothing listens there now
	_, port, _ := net.SplitHostPort(addr)
	withResolver(t, []string{"127.0.0.1"}, nil)
	if _, err := testDialer("svc.test").dial(context.Background(), "tcp", net.JoinHostPort("svc.test", port)); err == nil || errors.Is(err, ErrSSRFBlocked) {
		t.Errorf("dial(closed port) = %v, want the dial error", err)
	}
}

// TestIdentityProbeError: the probe's error names itself, should one
// ever be printed.
func TestIdentityProbeError(t *testing.T) {
	if got := (identityProbe{}).Error(); got != "fapihttp: identity probe" {
		t.Errorf("Error() = %q", got)
	}
}

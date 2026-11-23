package keys

import (
	"context"
	"errors"
	"flag"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"
)

// jwksRefreshPanicModeEnv names the scenario TestJWKSRefreshPanicChild
// runs.
const jwksRefreshPanicModeEnv = "FAPIGO_TEST_JWKS_REFRESH_PANIC_MODE"

// jwksRefreshPanicScenarios are TestJWKSRefreshPanicChild's scenarios,
// by mode: each makes a JWK Set refresh panic on the goroutine the cache
// starts for it.
var jwksRefreshPanicScenarios = map[string]func(t *testing.T){
	"fetch":              panicInFetch,
	"transport":          panicInClientJWKSTransport,
	"concurrent waiters": panicWithConcurrentRefreshWaiters,
}

// TestJWKSRefreshPanicLeavesProcessAlive runs each of
// TestJWKSRefreshPanicChild's scenarios in a child process: no caller
// can recover a panic on the refresh's goroutine, so one the cache
// didn't recover itself would end the child, not this test binary.
func TestJWKSRefreshPanicLeavesProcessAlive(t *testing.T) {
	if os.Getenv(jwksRefreshPanicModeEnv) != "" {
		t.Skip("running as the child")
	}
	for mode := range jwksRefreshPanicScenarios {
		t.Run(mode, func(t *testing.T) {
			runChildTest(t, "TestJWKSRefreshPanicChild", jwksRefreshPanicModeEnv+"="+mode)
		})
	}
}

// TestJWKSRefreshPanicChild runs the scenario jwksRefreshPanicModeEnv
// names, as TestJWKSRefreshPanicLeavesProcessAlive's child.
func TestJWKSRefreshPanicChild(t *testing.T) {
	scenario, ok := jwksRefreshPanicScenarios[os.Getenv(jwksRefreshPanicModeEnv)]
	if !ok {
		t.Skip("only runs as TestJWKSRefreshPanicLeavesProcessAlive's child")
	}
	scenario(t)
}

// runChildTest runs this test binary's test name alone in a child
// process, with env added to its environment, and fails t unless it
// passes. What the child covers is collected with this run's coverage.
func runChildTest(t *testing.T, name string, env ...string) {
	t.Helper()
	args := []string{"-test.run=^" + name + "$", "-test.v", "-test.count=1", "-test.timeout=2m"}
	if dir := flag.Lookup("test.gocoverdir"); dir != nil && dir.Value.String() != "" {
		args = append(args, "-test.gocoverdir="+dir.Value.String())
	}
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "--- PASS: "+name) {
		t.Fatalf("child %s (%s): %v\n%s", name, strings.Join(env, " "), err, out)
	}
}

// requireRefreshPanic fails t unless err is what a refresh that panicked
// with want gives each caller waiting on it: a refreshPanicError naming
// the panic and the stack it was recovered on.
func requireRefreshPanic(t *testing.T, err error, want string) {
	t.Helper()
	var panicked *refreshPanicError
	if !errors.As(err, &panicked) || !strings.Contains(err.Error(), "jwks refresh panicked: "+want) {
		t.Fatalf("resolution = %v, want the refresh's panic %q", err, want)
	}
	if !strings.Contains(err.Error(), "(*jwksCache[...]).runRefresh") {
		t.Fatalf("resolution = %v, want the stack the panic was recovered on", err)
	}
}

// requireRefreshDone fails t unless c has no refresh in flight and no
// failed fetch remembered.
func requireRefreshDone[V any](t *testing.T, c *jwksCache[V]) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.inflight != nil || c.lastRefreshErr != nil {
		t.Fatalf("once every caller returned: a refresh in flight = %v, a failed fetch remembered = %v; want neither", c.inflight != nil, c.lastRefreshErr)
	}
}

// panicInFetch: the fetch panics. The caller gets the panic as an
// error, and since a panic isn't remembered as the set's failed fetch,
// the next request fetches again.
func panicInFetch(t *testing.T) {
	var fetches atomic.Int32
	c := newJWKSCache(jwksCacheTiming{cacheTTL: time.Hour}.withDefaults(), time.Now, func(context.Context) ([]IssuerKey, error) {
		fetches.Add(1)
		panic("fetch bug")
	})
	for i := range 2 {
		_, err := c.current(context.Background())
		requireRefreshPanic(t, err, "fetch bug")
		requireRefreshDone(t, c)
		if got := fetches.Load(); got != int32(i+1) {
			t.Fatalf("%d fetches after %d requests, want one each", got, i+1)
		}
	}
}

// panickingTransport is a fapihttp.HTTPClient whose Do panics, as an
// embedder's transport with a bug would.
type panickingTransport struct{}

func (panickingTransport) Do(*http.Request) (*http.Response, error) {
	panic("transport bug")
}

// panicInClientJWKSTransport: a ClientJWKSSource whose fetcher's
// transport panics (outside production, which refuses such a fetcher)
// fails to resolve the client's keys, as a failed fetch of its jwks_uri
// does.
func panicInClientJWKSTransport(t *testing.T) {
	fetcher, err := fapihttp.New(panickingTransport{}, fapihttp.Config{
		MaxResponseBytes: 1 << 16, RequestTimeout: 5 * time.Second, MaxRedirects: 1, AllowLoopbackHosts: true,
	})
	if err != nil {
		t.Fatalf("fapihttp.New: %v", err)
	}
	jwksURI, err := fapi.ParseEndpointURL("https://127.0.0.1/jwks")
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	src, err := NewClientJWKSSource(fetcher, func(context.Context, fapi.ClientID) (fapi.URL, []byte, error) {
		return jwksURI, nil, nil
	})
	if err != nil {
		t.Fatalf("NewClientJWKSSource: %v", err)
	}
	set, err := src.ResolveVerificationKeys(context.Background(), ClientKeyRequest{ClientID: "client-1", Algorithm: fapi.ES256, KeyID: "k1"})
	requireRefreshPanic(t, err, "transport bug")
	if len(set.Keys) != 0 {
		t.Fatalf("ResolveVerificationKeys = %d keys with the error, want none", len(set.Keys))
	}
}

// panicWithConcurrentRefreshWaiters: every caller waiting on one refresh
// that panics gets the panic as an error, and none is left waiting. The
// refresh is put in flight, and every caller waits on it, before it
// runs, so all of them share its one fetch.
func panicWithConcurrentRefreshWaiters(t *testing.T) {
	var fetches atomic.Int32
	c := newJWKSCache(jwksCacheTiming{cacheTTL: time.Hour}.withDefaults(), time.Now, func(context.Context) ([]IssuerKey, error) {
		fetches.Add(1)
		panic("fetch bug")
	})
	call := &refreshCall[[]IssuerKey]{done: make(chan struct{})}
	c.mu.Lock()
	c.inflight = call
	c.mu.Unlock()
	const callers = 16
	errs := make(chan error, callers)
	for range callers {
		go func() {
			_, err := waitRefresh(context.Background(), call)
			errs <- err
		}()
	}
	c.runRefresh(context.Background(), call)
	for range callers {
		requireRefreshPanic(t, <-errs, "fetch bug")
	}
	requireRefreshDone(t, c)
	if n := fetches.Load(); n != 1 {
		t.Fatalf("%d fetches for %d callers waiting on one refresh, want 1", n, callers)
	}
}

// TestJWKSRefreshEndingWithoutResultFailsClosed: a refresh whose
// goroutine ends without returning or panicking, as a fetch calling
// runtime.Goexit makes it, fails its caller with an error rather than
// an empty set and no error. It runs in this process: Goexit ends only
// its goroutine.
func TestJWKSRefreshEndingWithoutResultFailsClosed(t *testing.T) {
	c := newJWKSCache(jwksCacheTiming{cacheTTL: time.Hour}.withDefaults(), time.Now, func(context.Context) ([]IssuerKey, error) {
		runtime.Goexit()
		return nil, nil
	})
	if _, err := c.current(context.Background()); !errors.Is(err, errRefreshUnfinished) {
		t.Fatalf("current = %v, want %v", err, errRefreshUnfinished)
	}
	requireRefreshDone(t, c)
}

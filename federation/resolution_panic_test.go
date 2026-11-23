package federation_test

import (
	"context"
	"errors"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/federation"
	"github.com/idfoundry/fapigo/storage"
)

// resolutionPanicModeEnv names the scenario TestResolutionPanicChild
// runs.
const resolutionPanicModeEnv = "FAPIGO_TEST_RESOLUTION_PANIC_MODE"

// resolutionPanicScenarios are TestResolutionPanicChild's scenarios, by
// mode: each makes something a Trust Chain resolution calls panic on the
// goroutine the repository starts for it.
var resolutionPanicScenarios = map[string]func(t *testing.T){
	"hook":                     panicInHook,
	"transport":                panicInTransport,
	"clock":                    panicInClock,
	"clock-after-registration": panicInClockAfterRegistration,
	"concurrent waiters":       panicWithConcurrentWaiters,
}

// TestResolutionPanicLeavesProcessAlive runs each of
// TestResolutionPanicChild's scenarios in a child process: no caller can
// recover a panic on the resolution's goroutine, so one the repository
// didn't recover itself would end the child, not this test binary.
func TestResolutionPanicLeavesProcessAlive(t *testing.T) {
	if os.Getenv(resolutionPanicModeEnv) != "" {
		t.Skip("running as the child")
	}
	for mode := range resolutionPanicScenarios {
		t.Run(mode, func(t *testing.T) {
			runChildTest(t, "TestResolutionPanicChild", resolutionPanicModeEnv+"="+mode)
		})
	}
}

// TestResolutionPanicChild runs the scenario resolutionPanicModeEnv
// names, as TestResolutionPanicLeavesProcessAlive's child.
func TestResolutionPanicChild(t *testing.T) {
	scenario, ok := resolutionPanicScenarios[os.Getenv(resolutionPanicModeEnv)]
	if !ok {
		t.Skip("only runs as TestResolutionPanicLeavesProcessAlive's child")
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

// repositoryOver is an AutomaticClientRepository resolving through
// fetcher, under a Trust Anchor no entity here chains to, with cfg and
// clock.
func repositoryOver(t *testing.T, fetcher *fapihttp.Client, cfg federation.AutomaticRegistrationConfig, clock federation.Clock) *federation.AutomaticClientRepository {
	t.Helper()
	resolver, err := federation.NewResolver(federation.Config{
		TrustAnchors: []federation.TrustAnchor{{EntityID: "https://ta.example.org", JWKS: jwksFor(t, "a", generateKey(t))}},
		Limits:       federation.Limits{MaxPathLength: 5, MaxAuthorityHints: 5, MaxStatementLifetime: 2 * time.Hour, MaxClockSkew: 5 * time.Second},
	}, federation.Dependencies{HTTP: fetcher, Clock: federation.SystemClock{}})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	repo, err := federation.NewAutomaticClientRepository(alwaysFailsRepository{}, resolver, fetcher, cfg, clock)
	if err != nil {
		t.Fatalf("NewAutomaticClientRepository: %v", err)
	}
	return repo
}

// unservedRepository is repositoryOver an entity server answering every
// fetch 404, so each resolution fails at once, and the Entity Identifier
// of an RP on it.
func unservedRepository(t *testing.T, cfg federation.AutomaticRegistrationConfig, clock federation.Clock) (*federation.AutomaticClientRepository, fapi.ClientID) {
	t.Helper()
	ts := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(ts.Close)
	return repositoryOver(t, fetcherFor(t, ts), cfg, clock), fapi.ClientID(ts.URL + "/rp")
}

// requireResolutionPanic fails t unless err is what a resolution that
// panicked with want gives each caller waiting on it: an error wrapping
// storage.ErrStoreUnavailable, naming the panic and the stack it was
// recovered on.
func requireResolutionPanic(t *testing.T, err error, want string) {
	t.Helper()
	if !errors.Is(err, storage.ErrStoreUnavailable) || !strings.Contains(err.Error(), "the resolution panicked: "+want) {
		t.Fatalf("ResolveClient = %v, want the resolution's panic %q, wrapping storage.ErrStoreUnavailable", err, want)
	}
	if !strings.Contains(err.Error(), "(*AutomaticClientRepository).runResolution") {
		t.Fatalf("ResolveClient = %v, want the stack the panic was recovered on", err)
	}
}

// requireResolutionsDone fails t unless repo has no resolution running
// or in flight, and remembers a failure for id exactly when remembered.
func requireResolutionsDone(t *testing.T, repo *federation.AutomaticClientRepository, id fapi.ClientID, remembered bool) {
	t.Helper()
	running, inflight, _, gotRemembered := federation.ResolutionState(repo, id)
	if running != 0 || inflight != 0 {
		t.Fatalf("%d resolutions running and %d in flight once every caller returned, want none", running, inflight)
	}
	if gotRemembered != remembered {
		t.Fatalf("a failure remembered for %q = %v, want %v", id, gotRemembered, remembered)
	}
}

// panicInHook: OnResolutionFailure panics. The caller gets the panic as
// an error, and the failure the hook was told about is remembered first,
// so the next request is answered from that memory: no second
// resolution, and no second call.
func panicInHook(t *testing.T) {
	var calls atomic.Int32
	cfg := validAutomaticRegistrationConfig()
	cfg.OnResolutionFailure = func(context.Context, fapi.ClientID, error) {
		calls.Add(1)
		panic("hook bug")
	}
	repo, id := unservedRepository(t, cfg, federation.SystemClock{})
	_, err := repo.ResolveClient(context.Background(), id)
	requireResolutionPanic(t, err, "hook bug")
	requireResolutionsDone(t, repo, id, true)

	_, err = repo.ResolveClient(context.Background(), id)
	if err == nil || errors.Is(err, storage.ErrStoreUnavailable) || calls.Load() != 1 {
		t.Fatalf("ResolveClient again = %v after %d hook calls, want the remembered failure and one call", err, calls.Load())
	}
}

// panickingTransport is a fapihttp.HTTPClient whose Do panics, as an
// embedder's transport with a bug would, counting its calls.
type panickingTransport struct{ calls *atomic.Int32 }

func (p panickingTransport) Do(*http.Request) (*http.Response, error) {
	p.calls.Add(1)
	panic("transport bug")
}

// panicInTransport: the fetcher's transport panics (outside production,
// which refuses such a fetcher). A panic says nothing about the
// client_id, so no failure is remembered for it: the next request
// resolves again.
func panicInTransport(t *testing.T) {
	var calls atomic.Int32
	fetcher, err := fapihttp.New(panickingTransport{calls: &calls}, fapihttp.Config{
		MaxResponseBytes: 1 << 16, RequestTimeout: 5 * time.Second, MaxRedirects: 1, AllowLoopbackHosts: true,
	})
	if err != nil {
		t.Fatalf("fapihttp.New: %v", err)
	}
	repo := repositoryOver(t, fetcher, validAutomaticRegistrationConfig(), federation.SystemClock{})
	const id fapi.ClientID = "https://127.0.0.1/rp"
	for i := range 2 {
		_, err := repo.ResolveClient(context.Background(), id)
		requireResolutionPanic(t, err, "transport bug")
		requireResolutionsDone(t, repo, id, false)
		if got := calls.Load(); got != int32(i+1) {
			t.Fatalf("transport called %d times after %d requests, want one fetch each", got, i+1)
		}
	}
}

// panickingClock answers its first answers calls, then panics.
type panickingClock struct {
	answers int32
	calls   atomic.Int32
}

func (c *panickingClock) Now() time.Time {
	if c.calls.Add(1) > c.answers {
		panic("clock bug")
	}
	return time.Now()
}

// panicInClock: the repository's Clock answers the request starting the
// resolution, then panics on the resolution's goroutine, where the
// failure would be remembered: nothing is remembered, and the hook isn't
// called.
func panicInClock(t *testing.T) {
	var hooked atomic.Bool
	cfg := validAutomaticRegistrationConfig()
	cfg.OnResolutionFailure = func(context.Context, fapi.ClientID, error) { hooked.Store(true) }
	repo, id := unservedRepository(t, cfg, &panickingClock{answers: 1})
	_, err := repo.ResolveClient(context.Background(), id)
	requireResolutionPanic(t, err, "clock bug")
	requireResolutionsDone(t, repo, id, false)
	if hooked.Load() {
		t.Fatal("OnResolutionFailure was called after the Clock panicked")
	}
}

// panicInClockAfterRegistration: the Trust Chain resolves, and the
// Clock panics as the registration is about to be cached. The
// repository's lock mustn't be held by then, or the resolution could
// never finish and every later request would wait on the lock for ever;
// nothing is cached.
func panicInClockAfterRegistration(t *testing.T) {
	f := setupAutomaticRegistrationFixture(t, rpMetadataBuilder(t))
	// The request's own read, then the registration's expiry.
	clock := &panickingClock{answers: 2}
	repo, err := federation.NewAutomaticClientRepository(alwaysFailsRepository{}, f.newResolver(t), f.fetcher, validAutomaticRegistrationConfig(), clock)
	if err != nil {
		t.Fatalf("NewAutomaticClientRepository: %v", err)
	}
	id := fapi.ClientID(f.rpID)
	done := make(chan error, 1)
	go func() {
		_, err := repo.ResolveClient(context.Background(), id)
		done <- err
	}()
	select {
	case err := <-done:
		requireResolutionPanic(t, err, "clock bug")
	case <-time.After(30 * time.Second):
		t.Fatal("ResolveClient didn't return: the panic left the repository's lock held")
	}
	requireResolutionsDone(t, repo, id, false)
	_, _, cached := federation.CachedChainPosition(repo, id)
	if cached {
		t.Fatal("a resolution that panicked cached its registration")
	}
}

// panicWithConcurrentWaiters: every caller waiting on one resolution
// whose hook panics gets the panic as an error; none is left waiting.
func panicWithConcurrentWaiters(t *testing.T) {
	ts, _, release := stallingEntityServer(t)
	cfg := validAutomaticRegistrationConfig()
	cfg.OnResolutionFailure = func(context.Context, fapi.ClientID, error) { panic("hook bug") }
	repo := stallingRepository(t, ts, cfg)
	id := fapi.ClientID(ts.URL + "/rp")
	const callers = 16
	errs := make(chan error, callers)
	for range callers {
		go func() {
			_, err := repo.ResolveClient(context.Background(), id)
			errs <- err
		}()
	}
	// The fetch is held until every caller waits on the one resolution,
	// so all of them share its panic.
	waitForWaiters(t, repo, id, callers)
	close(release)
	for range callers {
		requireResolutionPanic(t, <-errs, "hook bug")
	}
	requireResolutionsDone(t, repo, id, true)
}

// waitForWaiters returns once n callers wait on id's resolution.
func waitForWaiters(t *testing.T, repo *federation.AutomaticClientRepository, id fapi.ClientID, n int) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		_, _, waiters, _ := federation.ResolutionState(repo, id)
		if waiters == n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d callers wait on the resolution, want %d", waiters, n)
		}
		runtime.Gosched()
	}
}

// TestResolutionEndingWithoutResultFailsClosed: a resolution whose
// goroutine ends without returning or panicking, as OnResolutionFailure
// calling runtime.Goexit makes it, fails its caller with an error
// wrapping storage.ErrStoreUnavailable rather than handing it the zero
// registration. It runs in this process: Goexit ends only its
// goroutine.
func TestResolutionEndingWithoutResultFailsClosed(t *testing.T) {
	cfg := validAutomaticRegistrationConfig()
	cfg.OnResolutionFailure = func(context.Context, fapi.ClientID, error) { runtime.Goexit() }
	repo, id := unservedRepository(t, cfg, federation.SystemClock{})
	client, err := repo.ResolveClient(context.Background(), id)
	if !errors.Is(err, storage.ErrStoreUnavailable) || client.ID() != "" {
		t.Fatalf("ResolveClient = client %q, %v; want no client and an error wrapping storage.ErrStoreUnavailable", client.ID(), err)
	}
	requireResolutionsDone(t, repo, id, true)
}

// TestAbandonedResolutionFreesItsPlace: a resolution every caller has
// abandoned is forgotten at once but runs on, holding its place under
// MaxConcurrentResolutions, and frees that place when its goroutine ends,
// whether OnResolutionFailure returns or panics. Otherwise a caller
// cancelling its own requests mid-resolution would use the places up for
// good, and every new client_id would be refused. It runs in this
// process: the repository recovers the hook's panic.
func TestAbandonedResolutionFreesItsPlace(t *testing.T) {
	for name, panics := range map[string]bool{"returns": false, "panics": true} {
		t.Run(name, func(t *testing.T) { abandonResolutionInHook(t, panics) })
	}
}

// abandonResolutionInHook is TestAbandonedResolutionFreesItsPlace's
// scenario, with the abandoned resolution's OnResolutionFailure
// panicking once released when panics is set, and returning otherwise.
func abandonResolutionInHook(t *testing.T, panics bool) {
	var held atomic.Bool
	entered, release := make(chan struct{}), make(chan struct{})
	cfg := validAutomaticRegistrationConfig()
	cfg.MaxConcurrentResolutions = 1
	// Only the first resolution's hook is held, until release.
	cfg.OnResolutionFailure = func(context.Context, fapi.ClientID, error) {
		if !held.CompareAndSwap(false, true) {
			return
		}
		close(entered)
		<-release
		if panics {
			panic("hook bug")
		}
	}
	repo, id := unservedRepository(t, cfg, federation.SystemClock{})
	other := fapi.ClientID(string(id) + "-other")

	ctx, cancel := context.WithCancel(context.Background())
	abandoned := make(chan error, 1)
	go func() {
		_, err := repo.ResolveClient(ctx, id)
		abandoned <- err
	}()
	<-entered
	cancel()
	if err := <-abandoned; !errors.Is(err, context.Canceled) {
		t.Fatalf("ResolveClient = %v, want context.Canceled", err)
	}
	if _, err := repo.ResolveClient(context.Background(), other); !errors.Is(err, federation.ErrTooManyResolutions) {
		t.Fatalf("ResolveClient while the abandoned resolution runs = %v, want ErrTooManyResolutions", err)
	}

	close(release)
	if !waitFor(10*time.Second, func() bool {
		running, inflight, _, _ := federation.ResolutionState(repo, id)
		return running == 0 && inflight == 0
	}) {
		running, inflight, _, _ := federation.ResolutionState(repo, id)
		t.Fatalf("%d resolutions running and %d in flight once the abandoned one ended, want none", running, inflight)
	}
	requireResolutionsDone(t, repo, id, true)
	if _, err := repo.ResolveClient(context.Background(), other); err == nil || errors.Is(err, federation.ErrTooManyResolutions) {
		t.Fatalf("ResolveClient once the abandoned resolution ended = %v, want the fetch failure", err)
	}
}

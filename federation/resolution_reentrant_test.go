package federation_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/federation"
)

// reentrantGuard is how long a test in this file waits for a
// ResolveClient whose OnResolutionFailure calls ResolveClient again
// before calling it stuck.
const reentrantGuard = 5 * time.Second

// TestReentrantResolutionFailureHookReturns: an OnResolutionFailure
// hook that calls ResolveClient, with no deadline, for the client_id
// whose failure it reports gets that failure at once rather than
// waiting on the resolution calling it, so neither call is stuck and
// the resolution's place under MaxConcurrentResolutions frees. That
// holds when the failure is remembered as the hook runs and also when
// it isn't (here, remembered for less time than the hook takes).
func TestReentrantResolutionFailureHookReturns(t *testing.T) {
	for name, tc := range map[string]struct {
		hookTakes time.Duration
		hookCtx   bool
	}{
		"remembered, no context":     {},
		"remembered, hook's context": {hookCtx: true},
		"forgotten, no context":      {hookTakes: time.Minute},
		"forgotten, hook's context":  {hookTakes: time.Minute, hookCtx: true},
	} {
		t.Run(name, func(t *testing.T) {
			checkReentrantHook(t, tc.hookTakes, tc.hookCtx)
		})
	}
}

// checkReentrantHook resolves an RP that fails registration (it has no
// openid_relying_party metadata) through a repository allowing one
// resolution at a time, whose hook moves the clock on by hookTakes and
// then calls ResolveClient for the same client_id, with its own ctx if
// hookCtx is set or with none.
func checkReentrantHook(t *testing.T, hookTakes time.Duration, hookCtx bool) {
	f := setupAutomaticRegistrationFixture(t, nil)
	clock := &settableClock{now: f.now}
	inner := make(chan error, 1)
	cfg := validAutomaticRegistrationConfig()
	cfg.FailureCacheAge = time.Second
	cfg.MaxConcurrentResolutions = 1
	var repo *federation.AutomaticClientRepository
	cfg.OnResolutionFailure = func(ctx context.Context, id fapi.ClientID, _ error) {
		clock.set(clock.Now().Add(hookTakes))
		if !hookCtx {
			ctx = context.Background()
		}
		_, err := repo.ResolveClient(ctx, id)
		inner <- err
	}
	var err error
	repo, err = federation.NewAutomaticClientRepository(alwaysFailsRepository{}, f.newResolver(t), f.fetcher, cfg, clock)
	if err != nil {
		t.Fatalf("NewAutomaticClientRepository: %v", err)
	}

	awaitReentrantHook(t, repo, fapi.ClientID(f.rpID), inner)
}

// TestReentrantResolutionFailureHookReturnsWhenMemoryFull is
// TestReentrantResolutionFailureHookReturns with the failure not
// remembered because maxFailedResolutions others, which any caller
// can have resolved, fill the memory.
func TestReentrantResolutionFailureHookReturnsWhenMemoryFull(t *testing.T) {
	ts := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(ts.Close)
	target := fapi.ClientID(ts.URL + "/target")
	inner := make(chan error, 1)
	cfg := validAutomaticRegistrationConfig()
	cfg.MaxConcurrentResolutions = 1
	var repo *federation.AutomaticClientRepository
	cfg.OnResolutionFailure = func(_ context.Context, id fapi.ClientID, _ error) {
		if id == target {
			_, err := repo.ResolveClient(context.Background(), id)
			inner <- err
		}
	}
	repo = stallingRepository(t, ts, cfg)
	for i := range federation.MaxFailedResolutions {
		if _, err := repo.ResolveClient(context.Background(), fapi.ClientID(fmt.Sprintf("%s/rp%d", ts.URL, i))); err == nil {
			t.Fatalf("ResolveClient(rp%d) = nil error, want the fetch failure", i)
		}
	}
	awaitReentrantHook(t, repo, target, inner)
	if _, _, _, remembered := federation.ResolutionState(repo, target); remembered {
		t.Fatal("the target's failure is remembered, want the memory full")
	}
}

// awaitReentrantHook resolves id, whose resolution fails and whose
// OnResolutionFailure calls ResolveClient for id and sends what that
// returns on inner, and checks both return the failure, within
// reentrantGuard, leaving no resolution running.
func awaitReentrantHook(t *testing.T, repo *federation.AutomaticClientRepository, id fapi.ClientID, inner <-chan error) {
	t.Helper()
	outer := make(chan error, 1)
	go func() {
		_, err := repo.ResolveClient(context.Background(), id)
		outer <- err
	}()
	select {
	case err := <-outer:
		if err == nil || errors.Is(err, federation.ErrTooManyResolutions) {
			t.Fatalf("ResolveClient = %v, want the registration failure", err)
		}
	case <-time.After(reentrantGuard):
		_, otherErr := repo.ResolveClient(context.Background(), "https://other.example.invalid")
		t.Fatalf("ResolveClient whose hook calls ResolveClient for the same client_id still waiting after %v; an unrelated resolution meanwhile = %v", reentrantGuard, otherErr)
	}
	if err := <-inner; err == nil || errors.Is(err, federation.ErrTooManyResolutions) {
		t.Fatalf("the hook's own ResolveClient = %v, want the registration failure", err)
	}
	if running, inflight, _, _ := federation.ResolutionState(repo, id); running != 0 || inflight != 0 {
		t.Fatalf("after the resolution: %d running, %d in flight; want 0 and 0", running, inflight)
	}
}

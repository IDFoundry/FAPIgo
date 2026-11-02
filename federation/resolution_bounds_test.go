package federation_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/federation"
	"github.com/idfoundry/fapigo/storage"
)

// stallingEntityServer is a TLS server whose every response stalls until
// release is closed or the request is cancelled, counting the requests
// it is holding.
func stallingEntityServer(t *testing.T) (ts *httptest.Server, holding *atomic.Int32, release chan struct{}) {
	t.Helper()
	holding = new(atomic.Int32)
	release = make(chan struct{})
	ts = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		holding.Add(1)
		defer holding.Add(-1)
		select {
		case <-release:
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
		http.NotFound(w, nil)
	}))
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
		ts.Close()
	})
	return ts, holding, release
}

func stallingRepository(t *testing.T, ts *httptest.Server, cfg federation.AutomaticRegistrationConfig) *federation.AutomaticClientRepository {
	t.Helper()
	resolver, err := federation.NewResolver(federation.Config{
		TrustAnchors: []federation.TrustAnchor{{EntityID: "https://ta.example.org", JWKS: jwksFor(t, "a", generateKey(t))}},
		Limits:       federation.Limits{MaxPathLength: 5, MaxAuthorityHints: 5, MaxStatementLifetime: 2 * time.Hour, MaxClockSkew: 5 * time.Second},
	}, federation.Dependencies{HTTP: fetcherFor(t, ts), Clock: federation.SystemClock{}})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	repo, err := federation.NewAutomaticClientRepository(alwaysFailsRepository{}, resolver, fetcherFor(t, ts), cfg, federation.SystemClock{})
	if err != nil {
		t.Fatalf("NewAutomaticClientRepository: %v", err)
	}
	return repo
}

// waitFor polls cond until it holds or timeout passes.
func waitFor(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
	return true
}

// TestAutomaticRegistrationCancelsAbandonedResolution: a resolution
// every caller has given up on is cancelled, so callers naming distinct
// client_ids and hanging up at once don't leave outbound fetches running.
func TestAutomaticRegistrationCancelsAbandonedResolution(t *testing.T) {
	ts, holding, _ := stallingEntityServer(t)
	repo := stallingRepository(t, ts, validAutomaticRegistrationConfig())

	const callers = 50
	done := make(chan error, callers)
	for i := range callers {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			_, err := repo.ResolveClient(ctx, fapi.ClientID(fmt.Sprintf("%s/rp%d", ts.URL, i)))
			done <- err
		}()
	}
	for range callers {
		if err := <-done; !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("ResolveClient = %v, want context.DeadlineExceeded", err)
		}
	}
	if !waitFor(2*time.Second, func() bool { return holding.Load() == 0 }) {
		t.Fatalf("%d outbound fetches still running after every caller hung up, want 0", holding.Load())
	}
}

// TestAutomaticRegistrationCapsConcurrentResolutions: past
// MaxConcurrentResolutions a new resolution is refused at once with
// ErrTooManyResolutions (an unavailable store, not an unknown client),
// not reported or remembered as the client_id's failure; a caller
// joining a running resolution isn't refused, and a slot frees once a
// resolution ends.
func TestAutomaticRegistrationCapsConcurrentResolutions(t *testing.T) {
	ts, holding, release := stallingEntityServer(t)
	var reported atomic.Int32
	cfg := validAutomaticRegistrationConfig()
	cfg.MaxConcurrentResolutions = 2
	cfg.OnResolutionFailure = func(context.Context, fapi.ClientID, error) { reported.Add(1) }
	repo := stallingRepository(t, ts, cfg)

	running := make(chan error, 2)
	for i := range 2 {
		go func() {
			_, err := repo.ResolveClient(context.Background(), fapi.ClientID(fmt.Sprintf("%s/rp%d", ts.URL, i)))
			running <- err
		}()
	}
	if !waitFor(2*time.Second, func() bool { return holding.Load() == 2 }) {
		t.Fatalf("%d resolutions started, want 2", holding.Load())
	}

	extra := fapi.ClientID(ts.URL + "/extra")
	_, err := repo.ResolveClient(context.Background(), extra)
	if !errors.Is(err, federation.ErrTooManyResolutions) || !errors.Is(err, storage.ErrStoreUnavailable) {
		t.Fatalf("ResolveClient past the limit = %v, want ErrTooManyResolutions wrapping storage.ErrStoreUnavailable", err)
	}
	joinCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := repo.ResolveClient(joinCtx, fapi.ClientID(ts.URL+"/rp0")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ResolveClient joining a running resolution = %v, want context.DeadlineExceeded", err)
	}

	close(release)
	for range 2 {
		if err := <-running; err == nil || errors.Is(err, federation.ErrTooManyResolutions) {
			t.Fatalf("running ResolveClient = %v, want the fetch failure", err)
		}
	}
	_, err = repo.ResolveClient(context.Background(), extra)
	if err == nil || errors.Is(err, federation.ErrTooManyResolutions) {
		t.Fatalf("ResolveClient after slots freed = %v, want the fetch failure", err)
	}
	if n := reported.Load(); n != 3 {
		t.Fatalf("OnResolutionFailure called %d times, want 3 (the refusal isn't reported)", n)
	}
}

func TestNewAutomaticClientRepositoryRejectsNegativeMaxConcurrentResolutions(t *testing.T) {
	f := setupAutomaticRegistrationFixture(t, nil)
	cfg := validAutomaticRegistrationConfig()
	cfg.MaxConcurrentResolutions = -1
	if _, err := federation.NewAutomaticClientRepository(alwaysFailsRepository{}, f.newResolver(t), f.fetcher, cfg, fixedClock{now: f.now}); err == nil {
		t.Fatal("NewAutomaticClientRepository with negative MaxConcurrentResolutions = nil error, want error")
	}
}

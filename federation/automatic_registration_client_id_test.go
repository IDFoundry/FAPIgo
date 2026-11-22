package federation_test

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/federation"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/storage"
)

// inRequestBody returns id the way it reaches ResolveClient from a form:
// a substring of the whole request body (a value with nothing to unescape
// isn't copied), together with that body.
func inRequestBody(id string) (clientID fapi.ClientID, body string) {
	const name = "client_id="
	body = name + id + "&x=" + strings.Repeat("a", 64<<10)
	return fapi.ClientID(body[len(name) : len(name)+len(id)]), body
}

// sharesMemory reports whether s lies within body's memory, as a
// substring of it does: anything holding s holds all of body.
func sharesMemory(s, body string) bool {
	if s == "" || body == "" {
		return false
	}
	p := uintptr(unsafe.Pointer(unsafe.StringData(s)))
	start := uintptr(unsafe.Pointer(unsafe.StringData(body)))
	return start <= p && p < start+uintptr(len(body))
}

// checkKeepsNothingOf fails t if repo keeps a string sharing body's
// memory.
func checkKeepsNothingOf(t *testing.T, repo *federation.AutomaticClientRepository, body string) {
	t.Helper()
	for _, kept := range federation.RetainedStrings(repo) {
		if sharesMemory(kept, body) {
			t.Errorf("repository keeps %.60q, which shares the memory of the request body its client_id came in", kept)
		}
	}
}

// newFixtureRepository is an AutomaticClientRepository with cfg that
// registers clients through f's Trust Anchor, at f's time, and has none
// statically registered.
func newFixtureRepository(t *testing.T, f *automaticRegistrationFixture, cfg federation.AutomaticRegistrationConfig) *federation.AutomaticClientRepository {
	t.Helper()
	repo, err := federation.NewAutomaticClientRepository(alwaysFailsRepository{}, f.newResolver(t), f.fetcher, cfg, fixedClock{now: f.now})
	if err != nil {
		t.Fatalf("NewAutomaticClientRepository: %v", err)
	}
	return repo
}

// newAutomaticKeySource is repo's AutomaticClientKeySource, with no
// client's keys statically registered.
func newAutomaticKeySource(t *testing.T, repo *federation.AutomaticClientRepository) *federation.AutomaticClientKeySource {
	t.Helper()
	src, err := federation.NewAutomaticClientKeySource(alwaysFailsKeySource{}, repo)
	if err != nil {
		t.Fatalf("NewAutomaticClientKeySource: %v", err)
	}
	return src
}

// checkRefusesOverlongClientID fails t unless id, a well-formed Entity
// Identifier too long for automatic registration, is an unknown client to
// repo and src alike, and repo's error quotes only a prefix of it.
func checkRefusesOverlongClientID(t *testing.T, repo *federation.AutomaticClientRepository, src *federation.AutomaticClientKeySource, id fapi.ClientID) {
	t.Helper()
	n := len(id)
	if err := federation.ValidEntityID(string(id)); err != nil {
		t.Fatalf("ValidEntityID(%d-byte id) = %v, want it well-formed", n, err)
	}
	_, err := repo.ResolveClient(context.Background(), id)
	if err == nil || errors.Is(err, storage.ErrStoreUnavailable) {
		t.Fatalf("ResolveClient(%d-byte id) = %.200v, want an unknown client's error", n, err)
	}
	if len(err.Error()) > 512 {
		t.Errorf("ResolveClient(%d-byte id) error is %d bytes, want only a prefix of the id quoted", n, len(err.Error()))
	}
	_, err = src.ResolveVerificationKeys(context.Background(), keys.ClientKeyRequest{ClientID: id, Algorithm: fapi.ES256})
	if err == nil || errors.Is(err, storage.ErrStoreUnavailable) {
		t.Fatalf("ResolveVerificationKeys(%d-byte id) = %.200v, want an unknown client's error", n, err)
	}
}

// TestAutomaticClientRepositoryRefusesAnOverlongClientID: a client_id
// longer than any Entity Identifier automatic registration resolves is an
// unknown client, as one that isn't an Entity Identifier is, whichever way
// it's asked for: nothing is fetched, reported or kept for it, and its
// error quotes only a prefix of it. One at the limit still resolves.
func TestAutomaticClientRepositoryRefusesAnOverlongClientID(t *testing.T) {
	f := setupAutomaticRegistrationFixture(t, rpMetadataBuilder(t))
	var fetched atomic.Int32
	f.rpMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fetched.Add(1)
		http.NotFound(w, r)
	})
	var failures resolutionFailures
	cfg := validAutomaticRegistrationConfig()
	cfg.OnResolutionFailure = failures.record
	repo := newFixtureRepository(t, f, cfg)
	src := newAutomaticKeySource(t, repo)
	// entityID is a well-formed Entity Identifier of n bytes on the RP's
	// host, which answers 404 for it.
	entityID := func(n int) fapi.ClientID {
		return fapi.ClientID(f.rpID + "/" + strings.Repeat("a", n-len(f.rpID)-1))
	}

	for _, n := range []int{federation.MaxEntityIDBytes + 1, 1 << 20} {
		checkRefusesOverlongClientID(t, repo, src, entityID(n))
	}
	if n := fetched.Load(); n != 0 {
		t.Errorf("overlong client_ids were fetched %d times, want 0", n)
	}
	if len(failures.ids) != 0 {
		t.Errorf("OnResolutionFailure called %d times for overlong client_ids, want 0", len(failures.ids))
	}
	if kept := federation.RetainedStrings(repo); len(kept) != 0 {
		t.Errorf("repository keeps %d strings after overlong client_ids, want none", len(kept))
	}

	id := entityID(federation.MaxEntityIDBytes)
	_, err := repo.ResolveClient(context.Background(), id)
	if err == nil || errors.Is(err, storage.ErrStoreUnavailable) {
		t.Fatalf("ResolveClient(unresolvable id at the limit) = %.200v, want its resolution's error", err)
	}
	if n := fetched.Load(); n != 1 || len(failures.ids) != 1 || failures.ids[0] != id {
		t.Fatalf("id at the limit fetched %d times and reported %d times, want once each", n, len(failures.ids))
	}
	if !slices.Contains(federation.RetainedStrings(repo), string(id)) {
		t.Error("the failure of the id at the limit wasn't remembered")
	}
	if strings.Contains(err.Error(), string(id)) {
		t.Errorf("ResolveClient error quotes the whole %d-byte id, want only a prefix", len(id))
	}
}

// checkFailureReported fails t unless repo refuses id, a client_id read
// from body, and reports that failure to OnResolutionFailure (recorded in
// failures) once, by a client_id not sharing body's memory.
func checkFailureReported(t *testing.T, repo *federation.AutomaticClientRepository, failures *resolutionFailures, id fapi.ClientID, body string) {
	t.Helper()
	if _, err := repo.ResolveClient(context.Background(), id); err == nil {
		t.Fatal("ResolveClient(unresolvable client_id) = nil error, want error")
	}
	if len(failures.ids) != 1 {
		t.Fatalf("OnResolutionFailure called %d times, want 1", len(failures.ids))
	}
	if sharesMemory(string(failures.ids[0]), body) {
		t.Error("OnResolutionFailure's client_id shares the memory of the request body it came in")
	}
}

// checkFailureRemembered fails t unless repo, having reported id's failure
// once already (recorded in failures), refuses id again without reporting
// it again.
func checkFailureRemembered(t *testing.T, repo *federation.AutomaticClientRepository, failures *resolutionFailures, id fapi.ClientID) {
	t.Helper()
	if _, err := repo.ResolveClient(context.Background(), id); err == nil {
		t.Fatal("ResolveClient(remembered failure) = nil error, want error")
	}
	if len(failures.ids) != 1 {
		t.Fatalf("OnResolutionFailure called %d times, want once: the failure wasn't remembered", len(failures.ids))
	}
}

// TestAutomaticClientRepositoryKeepsItsOwnCopyOfAClientID: a client_id
// read from a form shares the memory of the whole request body, so
// nothing the repository keeps for it — the key of a resolution in
// flight, a remembered failure or a cached registration, a superior's
// list, the registered client's own ID — and no client_id it passes to
// OnResolutionFailure may be the caller's string.
func TestAutomaticClientRepositoryKeepsItsOwnCopyOfAClientID(t *testing.T) {
	f := setupAutomaticRegistrationFixture(t, rpMetadataBuilder(t))

	t.Run("registered", func(t *testing.T) {
		repo := newFixtureRepository(t, f, validAutomaticRegistrationConfig())
		id, body := inRequestBody(f.rpID)
		if _, err := repo.ResolveClient(context.Background(), id); err != nil {
			t.Fatalf("ResolveClient: %v", err)
		}
		if !slices.Contains(federation.RetainedStrings(repo), f.rpID) {
			t.Fatal("registration wasn't cached")
		}
		checkKeepsNothingOf(t, repo, body)
	})

	t.Run("keys resolved", func(t *testing.T) {
		repo := newFixtureRepository(t, f, validAutomaticRegistrationConfig())
		src := newAutomaticKeySource(t, repo)
		id, body := inRequestBody(f.rpID)
		if _, err := src.ResolveVerificationKeys(context.Background(), keys.ClientKeyRequest{ClientID: id, Algorithm: fapi.ES256}); err != nil {
			t.Fatalf("ResolveVerificationKeys: %v", err)
		}
		checkKeepsNothingOf(t, repo, body)
	})

	t.Run("failed", func(t *testing.T) {
		var failures resolutionFailures
		cfg := validAutomaticRegistrationConfig()
		cfg.OnResolutionFailure = failures.record
		repo := newFixtureRepository(t, f, cfg)
		id, body := inRequestBody(f.rpID + "/unregistered") // the RP's host answers 404
		checkFailureReported(t, repo, &failures, id, body)
		// Named again, the failure is answered from the cache, which
		// still keys it by its own copy.
		again, againBody := inRequestBody(f.rpID + "/unregistered")
		checkFailureRemembered(t, repo, &failures, again)
		checkKeepsNothingOf(t, repo, body)
		checkKeepsNothingOf(t, repo, againBody)
	})

	t.Run("in flight", func(t *testing.T) {
		ts, holding, release := stallingEntityServer(t)
		repo := stallingRepository(t, ts, validAutomaticRegistrationConfig())
		id, body := inRequestBody(ts.URL + "/rp")
		done := make(chan error, 1)
		go func() {
			_, err := repo.ResolveClient(context.Background(), id)
			done <- err
		}()
		if !waitFor(2*time.Second, func() bool { return holding.Load() == 1 }) {
			t.Fatalf("%d resolutions started, want 1", holding.Load())
		}
		checkKeepsNothingOf(t, repo, body)
		close(release)
		if err := <-done; err == nil {
			t.Fatal("ResolveClient = nil error, want the fetch failure")
		}
		checkKeepsNothingOf(t, repo, body)
	})
}

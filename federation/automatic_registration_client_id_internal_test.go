package federation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
	"unsafe"

	fapi "github.com/idfoundry/fapigo"
)

// settableTestClock is a Clock a test moves between calls.
type settableTestClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *settableTestClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *settableTestClock) set(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = now
}

// newResolveTestRepository is an AutomaticClientRepository at clock's
// time, with empty caches and neither resolver nor fetcher: resolving a
// client_id that isn't an Entity Identifier fails before either is
// needed, and isn't remembered.
func newResolveTestRepository(clock Clock) *AutomaticClientRepository {
	return &AutomaticClientRepository{
		clock:    clock,
		cfg:      AutomaticRegistrationConfig{FailureCacheAge: time.Minute},
		cache:    newRegistrationCache(),
		failures: make(map[fapi.ClientID]failedResolution),
		inflight: make(map[fapi.ClientID]*inflightResolution),
	}
}

// TestCachesKeepTheirOwnCopyOfAClientID: the failure and registration
// caches key what they keep by a copy of the client_id they're given,
// refreshing an entry included, so a client_id sharing the memory of the
// whole request body it came in doesn't keep that body alive, whatever
// the caller.
func TestCachesKeepTheirOwnCopyOfAClientID(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	const name, rp = "client_id=", "https://rp.example"
	body := name + rp + "&x=" + strings.Repeat("a", 64<<10)
	id := fapi.ClientID(body[len(name) : len(name)+len(rp)])
	inBody := func(s string) bool {
		p := uintptr(unsafe.Pointer(unsafe.StringData(s)))
		start := uintptr(unsafe.Pointer(unsafe.StringData(body)))
		return start <= p && p < start+uintptr(len(body))
	}

	repo := newResolveTestRepository(fixedTestClock{now: now})
	for range 2 {
		repo.rememberFailure(id, errors.New("federation: no path"), now)
		repo.cache.put(id, cachedClient{superior: "https://int.example", branch: "https://int.example", expiresAt: now.Add(time.Hour)}, now)
	}
	if len(repo.failures) != 1 || repo.cache.len() != 1 {
		t.Fatalf("failures = %d, registrations = %d, want 1 each", len(repo.failures), repo.cache.len())
	}
	for key := range repo.failures {
		if inBody(string(key)) {
			t.Error("the failure cache's key shares the request body's memory")
		}
	}
	for key, slot := range repo.cache.entries {
		if inBody(string(key)) || inBody(string(slot.elem.Value.(fapi.ClientID))) {
			t.Error("the registration cache's key, or its superior's list, shares the request body's memory")
		}
	}
}

// TestResolveForgetsAnExpiredFailureItFinds: a lookup that finds its
// client_id's failure expired deletes it, rather than only skipping it,
// even when no sweep of the whole cache is due.
func TestResolveForgetsAnExpiredFailureItFinds(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	repo := newResolveTestRepository(fixedTestClock{now: now})
	const id = fapi.ClientID("not-an-entity-id")
	remembered := errors.New("federation: no path")
	repo.rememberFailure(id, remembered, now.Add(-time.Minute)) // expires at now
	repo.failureSweepDue = now.Add(time.Hour)

	_, err := repo.resolve(context.Background(), id)
	if err == nil || err.Error() == remembered.Error() {
		t.Fatalf("resolve(client_id with an expired failure) = %v, want a new resolution's error", err)
	}
	if _, ok := repo.failures[id]; ok {
		t.Fatal("expired failure still remembered after the lookup that found it")
	}
}

// TestResolveSweepsExpiredFailuresBelowTheCap: the failures of
// client_ids never named again don't stay until the cache fills. The
// first lookup once FailureCacheAge has passed since the last sweep
// deletes every expired failure; between sweeps, a lookup costs no pass
// over the cache.
func TestResolveSweepsExpiredFailuresBelowTheCap(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := &settableTestClock{now: start}
	repo := newResolveTestRepository(clock)
	lookup := func(at time.Duration) {
		t.Helper()
		clock.set(start.Add(at))
		if _, err := repo.resolve(context.Background(), "not-an-entity-id"); err == nil {
			t.Fatal("resolve(\"not-an-entity-id\") = nil error, want error")
		}
	}

	lookup(0) // sweeps the empty cache; the next sweep is due a minute on
	failed := errors.New("federation: no path")
	const n = 100
	for i := range n {
		repo.rememberFailure(fapi.ClientID(fmt.Sprintf("https://rp%d.example", i)), failed, start.Add(10*time.Second))
	}
	lookup(time.Minute) // a sweep, before any has expired
	lookup(90 * time.Second)
	if len(repo.failures) != n {
		t.Fatalf("failures = %d after a lookup between sweeps, want all %d (expired, not yet swept)", len(repo.failures), n)
	}
	lookup(2 * time.Minute)
	if len(repo.failures) != 0 {
		t.Fatalf("failures = %d after the next sweep, want 0 (every one had expired)", len(repo.failures))
	}
}

// TestQuoteEntityIDQuotesAShortPrefix: an Entity Identifier is quoted
// whole up to maxQuotedEntityIDBytes, and a longer one only up to it, cut
// at a character boundary and marked as cut.
func TestQuoteEntityIDQuotesAShortPrefix(t *testing.T) {
	for _, id := range []string{"https://rp.example", strings.Repeat("a", maxQuotedEntityIDBytes)} {
		if got := quoteEntityID(id); got != strconv.Quote(id) {
			t.Errorf("quoteEntityID(%d bytes) = %s, want it whole", len(id), got)
		}
	}
	long := "https://rp.example/" + strings.Repeat("é", 1000) // the cut lands mid-character
	got, err := strconv.Unquote(quoteEntityID(long))
	if err != nil {
		t.Fatalf("quoteEntityID(long) isn't a quoted string: %v", err)
	}
	prefix, cut := strings.CutSuffix(got, "…")
	if !cut || !utf8.ValidString(prefix) || !strings.HasPrefix(long, prefix) ||
		len(prefix) > maxQuotedEntityIDBytes || len(prefix) <= maxQuotedEntityIDBytes-utf8.UTFMax {
		t.Fatalf("quoteEntityID(long) = %q, want a valid prefix of nearly %d bytes, marked …", got, maxQuotedEntityIDBytes)
	}
}

// TestResolutionErrorsQuoteAShortPrefixOfTheClientID: however resolving
// a client_id fails, the errors automatic registration builds quote only a
// short prefix of it, so a long client_id can't make the text that
// reaches logs and OnResolutionFailure long.
func TestResolutionErrorsQuoteAShortPrefixOfTheClientID(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/garbled/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", EntityStatementContentType)
		_, _ = w.Write([]byte("not a statement"))
	})
	ts := httptest.NewTLSServer(mux) // anything else: 404
	t.Cleanup(ts.Close)
	fetcher := testFetcher(t, ts)
	resolver, err := NewResolver(Config{
		TrustAnchors: []TrustAnchor{{EntityID: "https://ta.example.org", JWKS: json.RawMessage(testRPJWKS)}},
		Limits:       Limits{MaxPathLength: 5, MaxAuthorityHints: 5, MaxStatementLifetime: time.Hour, MaxClockSkew: 5 * time.Second},
	}, Dependencies{HTTP: fetcher, Clock: SystemClock{}})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	longID := func(prefix string) string {
		return prefix + strings.Repeat("a", maxEntityIDBytes-len(prefix))
	}
	unreachable, garbled, notEntityID := longID(ts.URL+"/missing/"), longID(ts.URL+"/garbled/"), longID("not-an-entity-id/")

	var reported []error
	repo := newResolveTestRepository(SystemClock{})
	repo.resolver, repo.fetcher = resolver, fetcher
	repo.cfg.OnResolutionFailure = func(_ context.Context, _ fapi.ClientID, err error) { reported = append(reported, err) }
	_, unreachableErr := repo.resolve(context.Background(), fapi.ClientID(unreachable))
	_, garbledErr := repo.resolve(context.Background(), fapi.ClientID(garbled))
	_, notEntityIDErr := repo.resolve(context.Background(), fapi.ClientID(notEntityID))
	busy := newResolveTestRepository(SystemClock{})
	busy.running = busy.maxConcurrentResolutions()
	_, busyErr := busy.resolve(context.Background(), fapi.ClientID(unreachable))
	if len(reported) != 2 {
		t.Fatalf("OnResolutionFailure called %d times, want 2 (the unreachable and garbled client_ids)", len(reported))
	}

	for _, c := range []struct {
		name, id, wantPrefix string
		err                  error
		// onlyPrefix is set when nothing the error wraps quotes the id
		// either: the fetcher's status error and the statement parser's
		// don't, while an Entity Identifier's own syntax errors quote it
		// whole (at most maxEntityIDBytes of it).
		onlyPrefix bool
	}{
		{"unreachable", unreachable, "federation: resolve client " + quoteEntityID(unreachable) + ": federation: fetch entity configuration for " + quoteEntityID(unreachable) + ": ", unreachableErr, true},
		{"unreachable, as reported", unreachable, "federation: resolve client " + quoteEntityID(unreachable) + ": ", reported[0], true},
		{"not a statement", garbled, "federation: resolve client " + quoteEntityID(garbled) + ": federation: parse entity configuration for " + quoteEntityID(garbled) + ": ", garbledErr, true},
		{"too many resolutions", unreachable, "federation: resolve client " + quoteEntityID(unreachable) + ": ", busyErr, true},
		{"not an Entity Identifier", notEntityID, "federation: " + quoteEntityID(notEntityID) + " is not a registered client", notEntityIDErr, false},
	} {
		if c.err == nil || !strings.HasPrefix(c.err.Error(), c.wantPrefix) {
			t.Errorf("%s: error = %.300v..., want it to start %q", c.name, c.err, c.wantPrefix)
			continue
		}
		if c.onlyPrefix && strings.Contains(c.err.Error(), c.id[:maxQuotedEntityIDBytes+1]) {
			t.Errorf("%s: error quotes more than %d bytes of the client_id", c.name, maxQuotedEntityIDBytes)
		}
	}
}

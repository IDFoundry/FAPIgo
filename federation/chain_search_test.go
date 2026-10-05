package federation_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/federation"
	intfed "github.com/idfoundry/fapigo/internal/federation"
)

// graphEntity is one entity of a test federation graph.
type graphEntity struct {
	id     string
	key    *ecdsa.PrivateKey
	jwks   json.RawMessage
	server *httptest.Server

	mu            sync.Mutex
	configFetches int
}

// federationGraph builds a federation from authority hints alone: each
// entity serves an Entity Configuration listing its hints, and a fetch
// endpoint answering for every entity that lists it as a hint.
type federationGraph struct {
	t        *testing.T
	now      time.Time
	entities map[string]*graphEntity

	// lifetimes, keyed "superior>subject", overrides the hour a
	// Subordinate Statement otherwise lasts.
	lifetimes map[string]time.Duration
}

func newFederationGraph(t *testing.T, names ...string) *federationGraph {
	t.Helper()
	g := &federationGraph{t: t, now: time.Now(), entities: map[string]*graphEntity{}}
	for _, name := range names {
		e := &graphEntity{key: generateKey(t)}
		e.jwks = jwksFor(t, name, e.key)
		e.server = httptest.NewTLSServer(http.NotFoundHandler())
		t.Cleanup(e.server.Close)
		e.id = e.server.URL
		g.entities[name] = e
	}
	return g
}

// link sets each entity's authority hints (by name) and serves the graph.
// An entity with no hints and no entry is served with none. A hint to a
// name not in the graph points at an address nothing answers.
func (g *federationGraph) link(hints map[string][]string) {
	g.t.Helper()
	subordinates := g.subordinateStatements(hints)
	for name, e := range g.entities {
		g.serve(name, e, g.hintIDs(hints[name]), subordinates[name])
	}
}

// subordinateStatements signs a Subordinate Statement from each superior
// in hints (that's in the graph) about each of its subordinates, keyed
// by superior name, then subject id.
func (g *federationGraph) subordinateStatements(hints map[string][]string) map[string]map[string]string {
	g.t.Helper()
	subordinates := map[string]map[string]string{}
	for sub, sups := range hints {
		for _, sup := range sups {
			superior, ok := g.entities[sup]
			if !ok {
				continue
			}
			lifetime := time.Hour
			if l, ok := g.lifetimes[sup+">"+sub]; ok {
				lifetime = l
			}
			token, err := intfed.Create(intfed.CreateParams{
				Signer: superior.key, Algorithm: fapi.ES256, KeyID: sup,
				Issuer: superior.id, Subject: g.entities[sub].id, Now: g.now, Lifetime: lifetime,
				JWKS: g.entities[sub].jwks,
			})
			if err != nil {
				g.t.Fatalf("intfed.Create: %v", err)
			}
			if subordinates[sup] == nil {
				subordinates[sup] = map[string]string{}
			}
			subordinates[sup][g.entities[sub].id] = token
		}
	}
	return subordinates
}

// hintIDs is names' Entity Identifiers, with an unreachable address for
// a name not in the graph.
func (g *federationGraph) hintIDs(names []string) []string {
	var ids []string
	for _, h := range names {
		if sup, ok := g.entities[h]; ok {
			ids = append(ids, sup.id)
		} else {
			ids = append(ids, "https://127.0.0.1:1/"+h) // unreachable
		}
	}
	return ids
}

// serve serves e's Entity Configuration, naming hintIDs as its authority
// hints, and a fetch endpoint for its subordinates' statements.
func (g *federationGraph) serve(name string, e *graphEntity, hintIDs []string, subordinates map[string]string) {
	g.t.Helper()
	config, err := intfed.Create(intfed.CreateParams{
		Signer: e.key, Algorithm: fapi.ES256, KeyID: name,
		Issuer: e.id, Subject: e.id, Now: g.now, Lifetime: time.Hour, JWKS: e.jwks,
		AuthorityHints: hintIDs,
		Metadata:       federationEntityMetadata(g.t, e.id+"/fetch"),
	})
	if err != nil {
		g.t.Fatalf("intfed.Create: %v", err)
	}
	mux := http.NewServeMux()
	serveConfig := serveStatement(config)
	mux.HandleFunc("/.well-known/openid-federation", func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		e.configFetches++
		e.mu.Unlock()
		serveConfig(w, r)
	})
	mux.HandleFunc("/fetch", serveFetch(subordinates))
	e.server.Config.Handler = mux
}

func (g *federationGraph) resolver(maxPathLength, maxAuthorityHints int, anchors ...string) *federation.Resolver {
	g.t.Helper()
	var servers []*httptest.Server
	for _, e := range g.entities {
		servers = append(servers, e.server)
	}
	var tas []federation.TrustAnchor
	for _, name := range anchors {
		tas = append(tas, federation.TrustAnchor{EntityID: g.entities[name].id, JWKS: g.entities[name].jwks})
	}
	r, err := federation.NewResolver(federation.Config{
		TrustAnchors: tas,
		Limits: federation.Limits{
			MaxPathLength: maxPathLength, MaxAuthorityHints: maxAuthorityHints,
			MaxStatementLifetime: 2 * time.Hour, MaxClockSkew: 5 * time.Second,
		},
	}, federation.Dependencies{HTTP: fetcherFor(g.t, servers...), Clock: fixedClock{now: g.now}})
	if err != nil {
		g.t.Fatalf("NewResolver: %v", err)
	}
	return r
}

func (g *federationGraph) chain(result federation.ResolvedEntity) []string {
	byID := map[string]string{}
	for name, e := range g.entities {
		byID[e.id] = name
	}
	var names []string
	for _, id := range result.Chain {
		names = append(names, byID[id])
	}
	return names
}

// TestResolveBacktracksPastADeadEnd: the leaf's first superior leads
// only to a Trust Anchor this resolver doesn't trust; its second reaches
// a trusted one. A first-reachable walk fails here.
func TestResolveBacktracksPastADeadEnd(t *testing.T) {
	g := newFederationGraph(t, "leaf", "other", "otherTA", "i1", "ta")
	g.link(map[string][]string{
		"leaf":  {"other", "i1"},
		"other": {"otherTA"},
		"i1":    {"ta"},
	})
	result, err := g.resolver(5, 5, "ta").Resolve(context.Background(), g.entities["leaf"].id)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := strings.Join(g.chain(result), ">"); got != "leaf>i1>ta" {
		t.Errorf("chain = %s, want leaf>i1>ta", got)
	}
	// Nothing from the abandoned branch is left in the chain's tokens:
	// the leaf's configuration, one statement per hop, and the Trust
	// Anchor's configuration.
	if len(result.Tokens) != len(result.Chain)+1 {
		t.Errorf("Tokens has %d entries, want %d", len(result.Tokens), len(result.Chain)+1)
	}
}

// TestResolvePrefersAConfiguredTrustAnchor: the leaf lists an
// Intermediate before the Trust Anchor itself; the chain goes straight to
// the Trust Anchor.
func TestResolvePrefersAConfiguredTrustAnchor(t *testing.T) {
	g := newFederationGraph(t, "leaf", "i1", "ta")
	g.link(map[string][]string{
		"leaf": {"i1", "ta"},
		"i1":   {"ta"},
	})
	result, err := g.resolver(5, 5, "ta").Resolve(context.Background(), g.entities["leaf"].id)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := strings.Join(g.chain(result), ">"); got != "leaf>ta" {
		t.Errorf("chain = %s, want leaf>ta", got)
	}
	if n := g.entities["i1"].configFetches; n != 0 {
		t.Errorf("i1's Entity Configuration fetched %d times, want 0: the Trust Anchor is tried first", n)
	}
}

// TestResolveSharedSuperiorFetchedOnce: two branches meet at one
// superior, whose Entity Configuration is fetched once (§10.1).
func TestResolveSharedSuperiorFetchedOnce(t *testing.T) {
	g := newFederationGraph(t, "leaf", "a", "b", "shared", "ta")
	g.link(map[string][]string{
		"leaf":   {"a", "b"},
		"a":      {"shared"},
		"b":      {"shared"},
		"shared": {"deadEnd"},
		"ta":     nil,
	})
	// shared leads nowhere trusted, so both branches are explored and fail.
	if _, err := g.resolver(5, 5, "ta").Resolve(context.Background(), g.entities["leaf"].id); err == nil {
		t.Fatal("Resolve = nil error, want no path")
	}
	if n := g.entities["shared"].configFetches; n != 1 {
		t.Errorf("shared's Entity Configuration fetched %d times, want 1", n)
	}
}

// TestResolveSearchIsBounded: exploring dead ends stops after
// MaxPathLength × MaxAuthorityHints superiors, however wide the graph.
func TestResolveSearchIsBounded(t *testing.T) {
	g := newFederationGraph(t, "leaf", "a", "b", "a1", "a2", "b1", "b2", "ta")
	g.link(map[string][]string{
		"leaf": {"a", "b"},
		"a":    {"a1", "a2"},
		"b":    {"b1", "b2"},
		"a1":   {"x1", "x2"},
		"a2":   {"x3", "x4"},
		"b1":   {"x5", "x6"},
		"b2":   {"x7", "x8"},
	})
	_, err := g.resolver(3, 2, "ta").Resolve(context.Background(), g.entities["leaf"].id)
	if err == nil || !strings.Contains(err.Error(), "stopped after trying 6 superiors") {
		t.Fatalf("Resolve = %v, want the search stopped after 6 superiors", err)
	}
	total := 0
	for _, e := range g.entities {
		total += e.configFetches
	}
	// The leaf's own configuration, plus at most 6 superiors tried.
	if total > 7 {
		t.Errorf("fetched %d Entity Configurations, want at most 7", total)
	}
}

// TestResolveReportsEveryFailedBranch: when no authority hint leads to a
// configured Trust Anchor, the error gives each branch's own reason, not
// only the last one tried.
func TestResolveReportsEveryFailedBranch(t *testing.T) {
	g := newFederationGraph(t, "leaf", "a", "untrusted", "b", "ta")
	g.link(map[string][]string{
		"leaf": {"a", "b"},
		"a":    {"untrusted"},
		"b":    {"unreachable"},
		"ta":   nil,
	})
	_, err := g.resolver(5, 5, "ta").Resolve(context.Background(), g.entities["leaf"].id)
	if err == nil {
		t.Fatal("Resolve = nil error, want no path")
	}
	msg := err.Error()
	for _, want := range []string{
		"via \"" + g.entities["a"].id + "\"",
		"via \"" + g.entities["b"].id + "\"",
		g.entities["untrusted"].id + "\" has no authority_hints",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("Resolve error = %q, want it to contain %q", msg, want)
		}
	}
}

// TestResolveMaxPathLengthCountsSuperiors pins what Limits.MaxPathLength
// counts: superiors (the Intermediates plus the Trust Anchor), so
// leaf>i1>i2>ta needs 3 and is refused at 2.
func TestResolveMaxPathLengthCountsSuperiors(t *testing.T) {
	for _, tc := range []struct {
		maxPathLength int
		wantErr       bool
	}{
		{2, true},
		{3, false},
	} {
		g := newFederationGraph(t, "leaf", "i1", "i2", "ta")
		g.link(map[string][]string{"leaf": {"i1"}, "i1": {"i2"}, "i2": {"ta"}})
		_, err := g.resolver(tc.maxPathLength, 5, "ta").Resolve(context.Background(), g.entities["leaf"].id)
		if tc.wantErr {
			if err == nil || !strings.Contains(err.Error(), "max path length (2 superiors") {
				t.Errorf("MaxPathLength=%d, 2 intermediates: Resolve = %v, want the max path length refusal", tc.maxPathLength, err)
			}
		} else if err != nil {
			t.Errorf("MaxPathLength=%d, 2 intermediates: Resolve = %v, want success", tc.maxPathLength, err)
		}
	}
}

// TestResolveBudgetErrorKeepsEarlierBranches: when the search budget
// runs out, the error still names the branches already tried and why
// each failed, not only that the budget ran out.
func TestResolveBudgetErrorKeepsEarlierBranches(t *testing.T) {
	g := newFederationGraph(t, "leaf", "a", "b", "a1", "a2", "ta")
	g.link(map[string][]string{
		"leaf": {"a", "b"},
		"a":    {"a1", "a2"},
		"a1":   {"x1", "x2"},
		"a2":   {"x3", "x4"},
	})
	_, err := g.resolver(3, 2, "ta").Resolve(context.Background(), g.entities["leaf"].id)
	if err == nil {
		t.Fatal("Resolve = nil error, want the search stopped")
	}
	msg := err.Error()
	for _, want := range []string{
		"stopped after trying 6 superiors",
		"via \"" + g.entities["a"].id + "\"",
		"via \"" + g.entities["a1"].id + "\"",
		"via \"https://127.0.0.1:1/x1\"",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("Resolve error = %q, want it to contain %q", msg, want)
		}
	}
}

// TestResolveErrorDoesNotRepeatAuthorityHints: an entity's authority
// hints are its own choice, so the error names each one only for the
// branch that tried it (and that branch's own failure), never as a whole
// list again at every level.
func TestResolveErrorDoesNotRepeatAuthorityHints(t *testing.T) {
	long := func(n int) string { return fmt.Sprintf("h%d-%s", n, strings.Repeat("x", 2000)) }
	g := newFederationGraph(t, "leaf", "i1", "i2", "ta")
	g.link(map[string][]string{
		"leaf": {"i1", long(1), long(2)},
		"i1":   {"i2", long(3), long(4)},
		"i2":   {long(5), long(6)},
	})
	_, err := g.resolver(5, 5, "ta").Resolve(context.Background(), g.entities["leaf"].id)
	if err == nil {
		t.Fatal("Resolve = nil error, want no path")
	}
	msg := err.Error()
	for n := 1; n <= 6; n++ {
		// Only within its own branch: the branch's "via", and its fetch
		// failure, which names the entity and the URL it couldn't reach.
		if got := strings.Count(msg, long(n)); got == 0 || got > 3 {
			t.Errorf("hint %d appears %d times in the error, want at most 3 (its own branch only)", n, got)
		}
	}
}

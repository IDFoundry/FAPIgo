package server_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/par"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// unusableRequestURIDescription is BeginAuthorization's description of a
// request_uri its store can't begin.
const unusableRequestURIDescription = "request_uri is invalid, expired, or already used"

// fakePushedRequestLookup reads a fakeTransactionStore's pushed
// requests, as memstore.NewPushedRequestLookup reads memstore's: what
// BeginAuthorization would begin at txn.Now, left in place.
type fakePushedRequestLookup struct{ store *fakeTransactionStore }

func (l fakePushedRequestLookup) LookupPushedRequest(_ context.Context, txn storage.LookupPushedRequestTransaction) (storage.PendingPushedRequest, error) {
	f := l.store
	f.mu.Lock()
	defer f.mu.Unlock()
	record, ok := f.byReference[txn.Reference]
	switch {
	case f.referenceCompleted[txn.Reference]:
		return storage.PendingPushedRequest{}, errors.New("request_uri already consumed")
	case !ok:
		return storage.PendingPushedRequest{}, errors.New("no such request_uri")
	case !txn.Now.Before(record.ExpiresAt):
		return storage.PendingPushedRequest{}, errors.New("request_uri has expired")
	}
	return storage.PendingPushedRequest{ClientID: record.ClientID, ExpiresAt: record.ExpiresAt}, nil
}

// Capabilities is a test-only assertion, the store's — see
// fakeClientRepository.Capabilities.
func (l fakePushedRequestLookup) Capabilities() storage.Capabilities { return l.store.Capabilities() }

// readsTransactions is the PushedRequestLookup reading h's own
// transaction store.
func readsTransactions(h harness) storage.PushedRequestLookup {
	return fakePushedRequestLookup{h.transactions}
}

// countingReplayStore is a fakeReplayStore that counts its UseOnce
// calls, recorded or refused alike: each is a write to a real store.
type countingReplayStore struct {
	*fakeReplayStore
	uses atomic.Int64
}

func (c *countingReplayStore) UseOnce(ctx context.Context, use storage.ReplayUse) error {
	c.uses.Add(1)
	return c.fakeReplayStore.UseOnce(ctx, use)
}

// slotHarness is a harness whose server counts the writes it makes to
// its replay store, with the counter.
type slotHarness struct {
	harness
	replay *countingReplayStore
}

// withPushedRequestLookup rebuilds base's server over a
// countingReplayStore, with lookup(base) as
// Dependencies.PushedRequestLookup, or none when lookup is nil.
func withPushedRequestLookup(t *testing.T, base harness, lookup func(harness) storage.PushedRequestLookup) slotHarness {
	t.Helper()
	replay := &countingReplayStore{fakeReplayStore: &fakeReplayStore{}}
	base.deps.Replay = replay
	if lookup != nil {
		base.deps.PushedRequestLookup = lookup(base)
	}
	srv, err := server.New(base.cfg, base.deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	base.server = srv
	return slotHarness{harness: base, replay: replay}
}

// begin calls BeginAuthorization for req, on s's server or, when later
// isn't zero, on one over the same stores whose clock reads later past
// s.now. It returns the action, with how many replay writes and
// interaction records the call added.
func (s slotHarness) begin(t *testing.T, ctx context.Context, req server.BeginAuthorizationRequest, later time.Duration) (action server.AuthorizationAction, replayWrites, interactions int) {
	t.Helper()
	srv := s.server
	if later != 0 {
		deps := s.deps
		deps.Clock = fixedClock{now: s.now.Add(later)}
		var err error
		if srv, err = server.New(s.cfg, deps); err != nil {
			t.Fatalf("server.New: %v", err)
		}
	}
	uses, stored := s.replay.uses.Load(), s.interactionRecords()
	action, err := srv.BeginAuthorization(ctx, req)
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	return action, int(s.replay.uses.Load() - uses), s.interactionRecords() - stored
}

// interactionRecords is how many interactions s's transaction store
// holds.
func (s slotHarness) interactionRecords() int {
	s.transactions.mu.Lock()
	defer s.transactions.mu.Unlock()
	return len(s.transactions.byHandle)
}

// wantRefusal checks action is a LocalErrorResponse with code and
// description.
func wantRefusal(t *testing.T, action server.AuthorizationAction, code server.ErrorCode, description string) {
	t.Helper()
	le, ok := action.(server.LocalErrorResponse)
	if !ok {
		t.Fatalf("action = %T, want a LocalErrorResponse", action)
	}
	if le.Error.Code() != code || le.Error.PublicDescription() != description {
		t.Fatalf("refusal = %s: %s, want %s: %s", le.Error.Code(), le.Error.PublicDescription(), code, description)
	}
}

// completeInteraction begins an interaction for req on h and completes
// it, consuming req's request_uri.
func completeInteraction(t *testing.T, h harness, req server.BeginAuthorizationRequest) {
	t.Helper()
	action, err := h.server.BeginAuthorization(context.Background(), req)
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	required, ok := action.(server.InteractionRequired)
	if !ok {
		t.Fatalf("action = %T, want InteractionRequired", action)
	}
	if _, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{Handle: required.Handle, Result: authorizeResult(t)}); err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
}

// unusableRequestURIs each set up, on h, a request_uri no interaction
// can be begun for: the request presenting it, and how far past h.now
// the server's clock reads when it's presented.
var unusableRequestURIs = []struct {
	name  string
	setup func(t *testing.T, h harness) (server.BeginAuthorizationRequest, time.Duration)
}{
	{"unknown", func(*testing.T, harness) (server.BeginAuthorizationRequest, time.Duration) {
		return server.BeginAuthorizationRequest{RequestURI: par.RequestURIPrefix + "never-pushed", ClientID: "nobody"}, 0
	}},
	{"another client_id", func(t *testing.T, h harness) (server.BeginAuthorizationRequest, time.Duration) {
		return server.BeginAuthorizationRequest{RequestURI: pushForInteractions(t, h), ClientID: "attacker"}, 0
	}},
	{"expired", func(t *testing.T, h harness) (server.BeginAuthorizationRequest, time.Duration) {
		return server.BeginAuthorizationRequest{RequestURI: pushForInteractions(t, h), ClientID: testClientID}, h.cfg.Limits.PushedRequestLifetime
	}},
	{"completed", func(t *testing.T, h harness) (server.BeginAuthorizationRequest, time.Duration) {
		req := server.BeginAuthorizationRequest{RequestURI: pushForInteractions(t, h), ClientID: testClientID}
		completeInteraction(t, h, req)
		return req, 0
	}},
}

// TestBeginAuthorizationRefusesUnusableRequestURIBeforeWriting: anyone
// can send a browser to the authorization endpoint, so with
// Dependencies.PushedRequestLookup set, a request_uri that is unknown,
// presented with another client_id, expired or already used gets the
// refusal it always got and writes nothing: no replay store write, no
// interaction. Without the lookup the refusal is the same, but it
// claims an interaction slot first.
func TestBeginAuthorizationRefusesUnusableRequestURIBeforeWriting(t *testing.T) {
	for _, tc := range unusableRequestURIs {
		for _, withLookup := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/lookup=%t", tc.name, withLookup), func(t *testing.T) {
				checkUnusableRequestURI(t, tc.setup, withLookup)
			})
		}
	}
}

func checkUnusableRequestURI(t *testing.T, setup func(*testing.T, harness) (server.BeginAuthorizationRequest, time.Duration), withLookup bool) {
	var lookup func(harness) storage.PushedRequestLookup
	if withLookup {
		lookup = readsTransactions
	}
	s := withPushedRequestLookup(t, newHarness(t, server.ProfileFAPISecurity, false), lookup)
	req, later := setup(t, s.harness)
	slots := interactionSlotRecords(s.replay.fakeReplayStore)
	action, writes, interactions := s.begin(t, context.Background(), req, later)
	wantRefusal(t, action, server.ErrorInvalidRequestURI, unusableRequestURIDescription)
	claimed := interactionSlotRecords(s.replay.fakeReplayStore) - slots
	switch {
	case interactions != 0:
		t.Fatalf("BeginAuthorization stored %d interactions, want none", interactions)
	case withLookup && writes != 0:
		t.Fatalf("BeginAuthorization with the lookup made %d replay writes, want none", writes)
	case !withLookup && claimed != 1:
		t.Fatalf("BeginAuthorization without the lookup claimed %d interaction slots, want 1", claimed)
	}
}

// failingPushedRequestLookup fails every lookup with err.
type failingPushedRequestLookup struct{ err error }

func (l failingPushedRequestLookup) LookupPushedRequest(context.Context, storage.LookupPushedRequestTransaction) (storage.PendingPushedRequest, error) {
	return storage.PendingPushedRequest{}, l.err
}

// TestBeginAuthorizationPushedRequestLookupOutage: a lookup that
// couldn't answer is a server error, not a request_uri refused as
// unusable, which a browser would show as a broken link; nothing is
// written.
func TestBeginAuthorizationPushedRequestLookupOutage(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		cancel bool
	}{
		{"store unavailable", fmt.Errorf("backend down: %w", storage.ErrStoreUnavailable), false},
		{"request cancelled", errors.New("lookup interrupted"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := withPushedRequestLookup(t, newHarness(t, server.ProfileFAPISecurity, false), func(harness) storage.PushedRequestLookup {
				return failingPushedRequestLookup{tc.err}
			})
			req := server.BeginAuthorizationRequest{RequestURI: pushForInteractions(t, s.harness), ClientID: testClientID}
			action, writes, interactions := s.begin(t, lookupContext(t, tc.cancel), req, 0)
			wantRefusal(t, action, server.ErrorServerError, "failed to look up the pushed authorization request")
			if status := action.(server.LocalErrorResponse).Error.HTTPStatus(); status != 500 {
				t.Errorf("HTTP status = %d, want 500", status)
			}
			if writes != 0 || interactions != 0 {
				t.Fatalf("BeginAuthorization made %d replay writes and stored %d interactions, want none", writes, interactions)
			}
		})
	}
}

// TestBeginAuthorizationGeneratesTheHandleAfterTheLookup: the
// interaction handle is drawn from Dependencies.Random after the lookup
// and before the slot claim. With a Random that fails, a request_uri the
// lookup refuses still gets its refusal, and a live one is a 500
// server_error that claims no slot.
func TestBeginAuthorizationGeneratesTheHandleAfterTheLookup(t *testing.T) {
	s := withPushedRequestLookup(t, newHarness(t, server.ProfileFAPISecurity, false), readsTransactions)
	live := server.BeginAuthorizationRequest{RequestURI: pushForInteractions(t, s.harness), ClientID: testClientID}
	s.deps.Random = iotest.ErrReader(errors.New("random source failed"))
	srv, err := server.New(s.cfg, s.deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	s.server = srv
	unknown := server.BeginAuthorizationRequest{RequestURI: par.RequestURIPrefix + "never-pushed", ClientID: testClientID}
	action, _, _ := s.begin(t, context.Background(), unknown, 0)
	wantRefusal(t, action, server.ErrorInvalidRequestURI, unusableRequestURIDescription)
	action, writes, interactions := s.begin(t, context.Background(), live, 0)
	wantRefusal(t, action, server.ErrorServerError, "failed to generate interaction handle")
	if writes != 0 || interactions != 0 {
		t.Fatalf("BeginAuthorization made %d replay writes and stored %d interactions, want none", writes, interactions)
	}
}

// staticPushedRequestLookup answers every lookup with pending, whatever
// the reference or txn.Now, as a lookup breaking its contract might.
type staticPushedRequestLookup struct{ pending storage.PendingPushedRequest }

func (l staticPushedRequestLookup) LookupPushedRequest(context.Context, storage.LookupPushedRequestTransaction) (storage.PendingPushedRequest, error) {
	return l.pending, nil
}

// TestBeginAuthorizationBackstopsPushedRequestLookup: a lookup that
// finds another client's request, or one that has expired, breaks its
// contract. The server refuses the request_uri anyway, live as it is,
// before writing anything, as it refuses such an answer from the store.
func TestBeginAuthorizationBackstopsPushedRequestLookup(t *testing.T) {
	for _, tc := range []struct {
		name      string
		clientID  fapi.ClientID
		expiresIn time.Duration
		want      string
	}{
		{"another client's request", "another-client", time.Minute, "client_id does not match the pushed authorization request"},
		{"an expired request", testClientID, 0, "request_uri has expired"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := withPushedRequestLookup(t, newHarness(t, server.ProfileFAPISecurity, false), func(h harness) storage.PushedRequestLookup {
				return staticPushedRequestLookup{storage.PendingPushedRequest{ClientID: tc.clientID, ExpiresAt: h.now.Add(tc.expiresIn)}}
			})
			req := server.BeginAuthorizationRequest{RequestURI: pushForInteractions(t, s.harness), ClientID: testClientID}
			action, writes, interactions := s.begin(t, context.Background(), req, 0)
			wantRefusal(t, action, server.ErrorInvalidRequestURI, tc.want)
			if writes != 0 || interactions != 0 {
				t.Fatalf("BeginAuthorization made %d replay writes and stored %d interactions, want none", writes, interactions)
			}
		})
	}
}

// TestBeginAuthorizationPushedRequestLookupIsAdvisory: a request_uri
// the lookup finds usable still has to claim an interaction slot and be
// begun by the store, which decides. A lookup that finds one the store
// doesn't hold, as a stale one could, lets through a slot but no
// interaction.
func TestBeginAuthorizationPushedRequestLookupIsAdvisory(t *testing.T) {
	s := withPushedRequestLookup(t, newHarness(t, server.ProfileFAPISecurity, false), func(h harness) storage.PushedRequestLookup {
		return staticPushedRequestLookup{storage.PendingPushedRequest{ClientID: testClientID, ExpiresAt: h.now.Add(time.Minute)}}
	})
	req := server.BeginAuthorizationRequest{RequestURI: par.RequestURIPrefix + "never-pushed", ClientID: testClientID}
	action, writes, interactions := s.begin(t, context.Background(), req, 0)
	wantRefusal(t, action, server.ErrorInvalidRequestURI, unusableRequestURIDescription)
	if writes != 1 || interactions != 0 {
		t.Fatalf("BeginAuthorization made %d replay writes and stored %d interactions, want 1 and 0", writes, interactions)
	}
}

// TestBeginAuthorizationPushedRequestLookupKeepsTheInteractionBound:
// with the lookup set, a live request_uri still begins at most eight
// interactions, each claiming its slot (see
// TestBeginAuthorizationBoundsInteractionsPerRequestURI).
func TestBeginAuthorizationPushedRequestLookupKeepsTheInteractionBound(t *testing.T) {
	s := withPushedRequestLookup(t, newHarness(t, server.ProfileFAPISecurity, false), readsTransactions)
	req := server.BeginAuthorizationRequest{RequestURI: pushForInteractions(t, s.harness), ClientID: testClientID}
	const gets = 12
	begun := 0
	for range gets {
		action, _, _ := s.begin(t, context.Background(), req, 0)
		if _, ok := action.(server.InteractionRequired); ok {
			begun++
			continue
		}
		wantRefusal(t, action, server.ErrorInvalidRequestURI, "request_uri has begun too many interactions")
	}
	if stored, slots := s.interactionRecords(), interactionSlotRecords(s.replay.fakeReplayStore); begun != 8 || stored != 8 || slots != 8 {
		t.Fatalf("%d GETs began %d interactions, stored %d and claimed %d slots, want 8 of each", gets, begun, stored, slots)
	}
}

// TestBeginAuthorizationWithMemstorePushedRequestLookup: memstore's
// lookup, over memstore's store, lets a live request_uri begin and
// refuses one already used before anything is written.
func TestBeginAuthorizationWithMemstorePushedRequestLookup(t *testing.T) {
	s := withPushedRequestLookup(t, newHarness(t, server.ProfileFAPISecurity, false), nil)
	transactions := memstore.NewTransactionStore()
	s.deps.Transactions = transactions
	s.deps.PushedRequestLookup = memstore.NewPushedRequestLookup(transactions)
	srv, err := server.New(s.cfg, s.deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	s.server = srv
	req := server.BeginAuthorizationRequest{RequestURI: pushForInteractions(t, s.harness), ClientID: testClientID}
	completeInteraction(t, s.harness, req)
	action, writes, _ := s.begin(t, context.Background(), req, 0)
	wantRefusal(t, action, server.ErrorInvalidRequestURI, unusableRequestURIDescription)
	if writes != 0 {
		t.Fatalf("BeginAuthorization of a used request_uri made %d replay writes, want none", writes)
	}
}

// declaredPushedRequestLookup is a PushedRequestLookup declaring caps.
type declaredPushedRequestLookup struct {
	failingPushedRequestLookup
	caps storage.Capabilities
}

func (l declaredPushedRequestLookup) Capabilities() storage.Capabilities { return l.caps }

// TestProductionChecksPushedRequestLookup: under AssuranceProduction the
// lookup declares storage.StoreAssurance as Transactions does: Durable,
// and CrossInstanceConsistent with DeploymentHorizontallyScaled.
func TestProductionChecksPushedRequestLookup(t *testing.T) {
	durable := storage.Capabilities{Durable: true}
	for name, tc := range map[string]struct {
		deployment server.Deployment
		lookup     storage.PushedRequestLookup
		want       string
	}{
		"memstore":                   {server.DeploymentSingleInstance, memstore.NewPushedRequestLookup(memstore.NewTransactionStore()), "pushed_request_lookup must implement storage.StoreAssurance"},
		"not durable":                {server.DeploymentSingleInstance, declaredPushedRequestLookup{caps: storage.Capabilities{}}, "pushed_request_lookup must declare Durable"},
		"durable":                    {server.DeploymentSingleInstance, declaredPushedRequestLookup{caps: durable}, ""},
		"scaled, not cross-instance": {server.DeploymentHorizontallyScaled, declaredPushedRequestLookup{caps: durable}, "pushed_request_lookup must declare CrossInstanceConsistent"},
		"scaled, cross-instance":     {server.DeploymentHorizontallyScaled, declaredPushedRequestLookup{caps: storage.Capabilities{Durable: true, CrossInstanceConsistent: true}}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, deps := productionConfigAndDeps(t)
			cfg.Deployment = tc.deployment
			deps.PushedRequestLookup = tc.lookup
			_, err := server.New(cfg, deps)
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("New(production, %s lookup) = %v, want nil", name, err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("New(production, %s lookup) = %v, want %q", name, err, tc.want)
			}
		})
	}
}

// pointerPushedRequestLookup implements PushedRequestLookup on a
// pointer, so a nil one is a typed nil.
type pointerPushedRequestLookup struct{}

func (*pointerPushedRequestLookup) LookupPushedRequest(context.Context, storage.LookupPushedRequestTransaction) (storage.PendingPushedRequest, error) {
	return storage.PendingPushedRequest{}, errors.New("pointerPushedRequestLookup answers nothing")
}

// TestNewRefusesTypedNilPushedRequestLookup: a nil pointer in
// Dependencies.PushedRequestLookup isn't == nil, so BeginAuthorization
// would call it; New refuses it, as it refuses a typed nil in any other
// field.
func TestNewRefusesTypedNilPushedRequestLookup(t *testing.T) {
	deps := validDependencies()
	deps.PushedRequestLookup = (*pointerPushedRequestLookup)(nil)
	if _, err := server.New(validConfig(t), deps); err == nil || !strings.Contains(err.Error(), "pushed_request_lookup is a nil") {
		t.Fatalf("New(a nil *pointerPushedRequestLookup) = %v, want the typed nil refused", err)
	}
}

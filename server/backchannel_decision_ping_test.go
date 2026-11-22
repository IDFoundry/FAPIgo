package server_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// pingInboxHarness is a CIBA harness over store whose testClientID is
// registered for ping delivery, notified through notifier, filing
// requests for user-1 in a memstore inbox, with room for 16 of them
// pending from testClientID: more than a bulk denial notifies at once.
// mutateDeps, when set, changes the dependencies last.
func pingInboxHarness(t *testing.T, store storage.BackchannelAuthenticationStore, notifier server.BackchannelNotifier, mutateDeps func(*server.Dependencies)) harness {
	t.Helper()
	ping := pingClientForDeclinedNotifier(t)
	return newHarnessWithBackchannelOptions(t, store, func(c *server.Config) {
		c.Limits.MaxPendingBackchannelAuthenticationRequestsPerClient = 16
	}, func(d *server.Dependencies) {
		d.Clients.(*fakeClientRepository).clients[testClientID] = ping
		d.BackchannelNotifier = notifier
		d.BackchannelSubjects = hintSubjects{known: map[string]bool{"user-1": true}}
		d.BackchannelInbox = memstore.NewBackchannelInbox()
		if mutateDeps != nil {
			mutateDeps(d)
		}
	})
}

// beginPings files n ping requests from testClientID for user-1, the
// i-th with client_notification_token "notify-me-i".
func beginPings(t *testing.T, h harness, n int) []server.BackchannelInteractionRequired {
	t.Helper()
	var filed []server.BackchannelInteractionRequired
	for i := range n {
		params := standardBackchannelParams(t)
		params["client_notification_token"] = jsonRaw(t, fmt.Sprintf("notify-me-%d", i))
		action, err := h.server.BeginBackchannelAuthentication(context.Background(), server.BeginBackchannelAuthenticationRequest{
			HTTP: server.FormRequest{Parameters: backchannelFormParams(h.clientAssertion(t), h.backchannelRequestObject(t, params))},
		})
		if err != nil {
			t.Fatalf("BeginBackchannelAuthentication: %v", err)
		}
		filed = append(filed, requireFiled(t, action, fmt.Sprintf("ping request %d", i)))
	}
	return filed
}

// requireDenied checks that each of pending is denied, its client's
// first poll answered access_denied, and that none is left in user-1's
// inbox.
func requireDenied(t *testing.T, h harness, pending []server.BackchannelInteractionRequired) {
	t.Helper()
	for _, p := range pending {
		if _, err := exchangeCIBA(t, h, p.AuthReqID.String()); serverErrorCode(t, err) != server.ErrorAccessDenied {
			t.Errorf("poll for a request the bulk denial took = %v, want access_denied", err)
		}
	}
	if left := inboxOf(t, h, "user-1"); len(left) != 0 {
		t.Errorf("inbox of user-1 = %d requests, want every one denied", len(left))
	}
}

// callbackNotifier hands each notification to notify, counting them.
type callbackNotifier struct {
	calls  atomic.Int32
	notify func(context.Context, server.BackchannelNotification) error
}

func (n *callbackNotifier) Notify(ctx context.Context, notification server.BackchannelNotification) error {
	n.calls.Add(1)
	return n.notify(ctx, notification)
}

// stallingNotifier stands for notification endpoints that take each
// notification and don't answer: Notify returns once release is closed
// (releaseAll), and otherwise fails once timeout has passed or its
// context has ended, as backchannelhttp's does. It counts the
// notifications sent, and how many were in flight at once.
type stallingNotifier struct {
	timeout time.Duration
	release chan struct{}
	once    sync.Once

	mu                           sync.Mutex
	calls, inFlight, maxInFlight int
}

func newStallingNotifier(timeout time.Duration) *stallingNotifier {
	return &stallingNotifier{timeout: timeout, release: make(chan struct{})}
}

func (n *stallingNotifier) Notify(ctx context.Context, _ server.BackchannelNotification) error {
	n.mu.Lock()
	n.calls++
	n.inFlight++
	n.maxInFlight = max(n.maxInFlight, n.inFlight)
	n.mu.Unlock()
	defer func() {
		n.mu.Lock()
		n.inFlight--
		n.mu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(ctx, n.timeout)
	defer cancel()
	select {
	case <-n.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (n *stallingNotifier) releaseAll() { n.once.Do(func() { close(n.release) }) }

// counts returns the notifications sent, in flight now and in flight at
// most.
func (n *stallingNotifier) counts() (calls, inFlight, maxInFlight int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.calls, n.inFlight, n.maxInFlight
}

// liveContextAuditSink records an event only while its context is live,
// as a sink writing to a database on the caller's context does.
type liveContextAuditSink struct{ fakeAuditSink }

func (s *liveContextAuditSink) Record(ctx context.Context, event server.AuditEvent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.fakeAuditSink.Record(ctx, event)
}

// completions counts the CompleteBackchannelAuthentication successes
// recorded.
func (s *liveContextAuditSink) completions() int {
	n := 0
	for _, event := range s.all() {
		if event.Type == server.AuditEventCompleteBackchannelAuthentication && event.Outcome == server.AuditOutcomeSuccess {
			n++
		}
	}
	return n
}

// TestCompleteBackchannelAuthenticationPingsOnceDecided: a ping client is
// notified only once its request is decided, out of its user's inbox and
// audited. A client polling as it's pinged gets the outcome, and the
// caller's context ending mid-ping, as a device's deadline does while the
// client's endpoint doesn't answer, costs neither the removal from the
// inbox nor the audit event, even with a sink that honours ctx.
func TestCompleteBackchannelAuthenticationPingsOnceDecided(t *testing.T) {
	audit := &liveContextAuditSink{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var (
		h                harness
		listedAtPing     bool
		auditedAtPing    int
		pollAtPing       server.TokenResult
		pollAtPingFailed error
	)
	notifier := &callbackNotifier{notify: func(pingCtx context.Context, notification server.BackchannelNotification) error {
		listedAtPing = len(inboxOf(t, h, "user-1")) != 0
		auditedAtPing = audit.completions()
		pollAtPing, pollAtPingFailed = exchangeCIBA(t, h, notification.AuthReqID)
		cancel() // the caller's deadline passes, the endpoint still silent
		<-pingCtx.Done()
		return pingCtx.Err()
	}}
	h = pingInboxHarness(t, memstore.NewBackchannelAuthenticationStore(), notifier, func(d *server.Dependencies) { d.Audit = audit })
	required := beginPings(t, h, 1)[0]

	authenticated, err := server.NewAuthenticatedSubject(mustSubjectID(t, "user-1"))
	if err != nil {
		t.Fatal(err)
	}
	authCtx, err := server.NewAuthenticationContext(h.now, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.server.CompleteBackchannelAuthentication(ctx, server.CompleteBackchannelAuthenticationRequest{
		Handle: required.Handle,
		Result: server.Authorize(authenticated, authCtx, server.GrantedAuthorization{Scope: required.Interaction.Scope}),
	}); err != nil {
		t.Fatalf("CompleteBackchannelAuthentication with its context ending mid-ping = %v, want nil", err)
	}

	if calls := notifier.calls.Load(); calls != 1 {
		t.Fatalf("%d notifications sent, want 1", calls)
	}
	if listedAtPing {
		t.Error("the request was still in its user's inbox when its client was pinged")
	}
	if auditedAtPing != 1 {
		t.Errorf("%d decisions audited when the client was pinged, want 1", auditedAtPing)
	}
	assertTokensOrAccessDenied(t, pollAtPing, pollAtPingFailed, false)
	if audited := audit.completions(); audited != 1 {
		t.Errorf("%d decisions audited, want 1 recorded before the context ended", audited)
	}
	if left := inboxOf(t, h, "user-1"); len(left) != 0 {
		t.Errorf("inbox of user-1 = %d requests, want the decided one gone", len(left))
	}
}

// TestCompleteBackchannelAuthenticationRefusesInteractionNeeded:
// InteractionNeeded answers a redirect's prompt=none, so CIBA refuses it
// with server_error, recording nothing and notifying no one; the request
// is still listed, and can still be decided.
func TestCompleteBackchannelAuthenticationRefusesInteractionNeeded(t *testing.T) {
	notifier := &fakeBackchannelNotifier{}
	h := pingInboxHarness(t, memstore.NewBackchannelAuthenticationStore(), notifier, nil)
	pending := beginPings(t, h, 1)

	err := h.server.CompleteBackchannelAuthentication(context.Background(), server.CompleteBackchannelAuthenticationRequest{
		Handle: pending[0].Handle, Result: server.InteractionNeeded(server.NeedLogin, "no session"),
	})
	if serverErrorCode(t, err) != server.ErrorServerError {
		t.Fatalf("CompleteBackchannelAuthentication(InteractionNeeded) = %v, want server_error", err)
	}
	if calls := notifier.callCount(); calls != 0 {
		t.Errorf("%d notifications sent for a refused decision, want none", calls)
	}
	if left := inboxOf(t, h, "user-1"); len(left) != 1 {
		t.Fatalf("inbox of user-1 = %d requests, want the undecided one still listed", len(left))
	}
	if err := h.server.CompleteBackchannelAuthentication(context.Background(), server.CompleteBackchannelAuthenticationRequest{
		Handle: pending[0].Handle, Result: server.Deny("declined"),
	}); err != nil {
		t.Fatalf("CompleteBackchannelAuthentication(Deny) after the refusal = %v, want nil", err)
	}
	if calls := notifier.callCount(); calls != 1 {
		t.Errorf("%d notifications sent once denied, want 1", calls)
	}
}

// TestDenyBackchannelInteractionsPingsEightAtATime: a bulk denial records
// every denial before it notifies anyone, then sends the notifications
// eight at a time. With the client's endpoint holding all ten
// notifications, eight are in flight, every request is already denied
// and out of the inbox, and the client's poll for each already gets
// access_denied.
func TestDenyBackchannelInteractionsPingsEightAtATime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		notifier := newStallingNotifier(time.Hour)
		defer notifier.releaseAll()
		h := pingInboxHarness(t, memstore.NewBackchannelAuthenticationStore(), notifier, nil)
		pending := beginPings(t, h, 10)
		subject := mustSubjectID(t, "user-1")
		type outcome struct {
			denied int
			err    error
		}
		done := make(chan outcome, 1)
		go func() {
			denied, err := h.server.DenyBackchannelInteractions(context.Background(), subject, "the account was closed")
			done <- outcome{denied, err}
		}()

		synctest.Wait()
		if _, inFlight, _ := notifier.counts(); inFlight != 8 {
			t.Errorf("%d notifications in flight, want 8", inFlight)
		}
		requireDenied(t, h, pending)

		notifier.releaseAll()
		got := <-done
		if got.err != nil || got.denied != len(pending) {
			t.Fatalf("DenyBackchannelInteractions = %d, %v; want %d, nil", got.denied, got.err, len(pending))
		}
		if calls, _, maxInFlight := notifier.counts(); calls != len(pending) || maxInFlight != 8 {
			t.Errorf("%d notifications sent, at most %d at once; want %d, 8 at once", calls, maxInFlight, len(pending))
		}
	})
}

// contextBackchannelStore fails every lookup once its context has
// ended, as a database does.
type contextBackchannelStore struct {
	storage.BackchannelAuthenticationStore
}

func (s contextBackchannelStore) LookupBackchannelAuthentication(ctx context.Context, handleHash [32]byte) (storage.LookedUpBackchannelAuthentication, error) {
	if err := ctx.Err(); err != nil {
		return storage.LookedUpBackchannelAuthentication{}, fmt.Errorf("db: %w", err)
	}
	return s.BackchannelAuthenticationStore.LookupBackchannelAuthentication(ctx, handleHash)
}

// TestDenyBackchannelInteractionsOnADeadline: with the client's endpoint
// silent until the notifier gives up, a bulk denial on a deadline still
// records every denial, on a store that honours ctx, and takes one
// notifier timeout for the notifications sent together, not one for
// each request.
func TestDenyBackchannelInteractionsOnADeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const pingTimeout = 10 * time.Second
		notifier := newStallingNotifier(pingTimeout)
		h := pingInboxHarness(t, contextBackchannelStore{memstore.NewBackchannelAuthenticationStore()}, notifier, nil)
		pending := beginPings(t, h, 8)
		ctx, cancel := context.WithTimeout(context.Background(), 3*pingTimeout)
		defer cancel()

		start := time.Now()
		denied, err := h.server.DenyBackchannelInteractions(ctx, mustSubjectID(t, "user-1"), "the account was closed")
		took := time.Since(start)
		if err != nil || denied != len(pending) {
			t.Fatalf("DenyBackchannelInteractions = %d, %v; want %d, nil", denied, err, len(pending))
		}
		if took != pingTimeout {
			t.Errorf("DenyBackchannelInteractions took %v, want one notifier timeout, %v", took, pingTimeout)
		}
		if calls, _, _ := notifier.counts(); calls != len(pending) {
			t.Errorf("%d notifications sent, want %d", calls, len(pending))
		}
		requireDenied(t, h, pending)
	})
}

// failingDecisionStore fails the decision on the request whose handle
// hashes to fail, as a store that can't answer does.
type failingDecisionStore struct {
	storage.BackchannelAuthenticationStore
	fail [32]byte
}

func (s *failingDecisionStore) DecideBackchannelAuthentication(ctx context.Context, decision storage.DecideBackchannelAuthentication) (storage.DecidedBackchannelAuthentication, error) {
	if decision.HandleHash == s.fail {
		return storage.DecidedBackchannelAuthentication{}, fmt.Errorf("db: %w", storage.ErrStoreUnavailable)
	}
	return s.BackchannelAuthenticationStore.DecideBackchannelAuthentication(ctx, decision)
}

// notifiedTokens returns the client_notification_token of each
// notification f was sent, sorted.
func (f *fakeBackchannelNotifier) notifiedTokens() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var tokens []string
	for _, call := range f.calls {
		tokens = append(tokens, call.ClientNotificationToken.Reveal())
	}
	slices.Sort(tokens)
	return tokens
}

// TestDenyBackchannelInteractionsPingsOnlyWhatItDenied: a denial the
// store fails doesn't stop a bulk denial, which records the others,
// notifies their clients alone and reports the failure. The request it
// failed to deny is still listed, so calling again finishes the job.
func TestDenyBackchannelInteractionsPingsOnlyWhatItDenied(t *testing.T) {
	store := &failingDecisionStore{BackchannelAuthenticationStore: memstore.NewBackchannelAuthenticationStore()}
	notifier := &fakeBackchannelNotifier{}
	h := pingInboxHarness(t, store, notifier, nil)
	pending := beginPings(t, h, 4)
	store.fail = sha256.Sum256([]byte(pending[0].Handle.String()))
	subject := mustSubjectID(t, "user-1")

	denied, err := h.server.DenyBackchannelInteractions(context.Background(), subject, "the account was closed")
	if denied != 3 || !errors.Is(err, storage.ErrStoreUnavailable) {
		t.Fatalf("DenyBackchannelInteractions with one denial failing = %d, %v; want 3 and the store's failure", denied, err)
	}
	if got, want := notifier.notifiedTokens(), []string{"notify-me-1", "notify-me-2", "notify-me-3"}; !slices.Equal(got, want) {
		t.Errorf("clients notified with %v, want %v: those denied", got, want)
	}
	if left := inboxOf(t, h, "user-1"); len(left) != 1 || left[0].Handle.String() != pending[0].Handle.String() {
		t.Fatalf("inbox of user-1 = %d requests, want only the one not denied", len(left))
	}

	store.fail = [32]byte{}
	if denied, err := h.server.DenyBackchannelInteractions(context.Background(), subject, "the account was closed"); err != nil || denied != 1 {
		t.Fatalf("DenyBackchannelInteractions again = %d, %v; want 1, nil", denied, err)
	}
	if calls := notifier.callCount(); calls != 4 {
		t.Errorf("%d notifications sent in all, want 4", calls)
	}
	requireDenied(t, h, pending)
}

// TestDenyBackchannelInteractionsRaisesANotifierPanic: a notifier that
// panics during a bulk denial doesn't take the process down from a
// goroutine of the server's: every denial is recorded and every other
// client notified, and the panic reaches the caller, as a single
// decision's would.
func TestDenyBackchannelInteractionsRaisesANotifierPanic(t *testing.T) {
	notifier := &callbackNotifier{notify: func(_ context.Context, notification server.BackchannelNotification) error {
		if notification.ClientNotificationToken.Reveal() == "notify-me-0" {
			panic("notifier bug")
		}
		return nil
	}}
	h := pingInboxHarness(t, memstore.NewBackchannelAuthenticationStore(), notifier, nil)
	pending := beginPings(t, h, 3)
	subject := mustSubjectID(t, "user-1")

	recovered := func() (recovered any) {
		defer func() { recovered = recover() }()
		_, _ = h.server.DenyBackchannelInteractions(context.Background(), subject, "the account was closed")
		return nil
	}()
	if recovered != "notifier bug" {
		t.Fatalf("DenyBackchannelInteractions with a panicking notifier panicked with %v, want the notifier's panic", recovered)
	}
	if calls := notifier.calls.Load(); calls != 3 {
		t.Errorf("%d notifications sent, want 3", calls)
	}
	requireDenied(t, h, pending)
}

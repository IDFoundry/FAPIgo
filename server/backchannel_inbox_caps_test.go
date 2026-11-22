package server_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/internal/requestobject"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// recordingInbox is a memstore inbox recording the entries it's asked
// to add and remove, whose listing fails with listErr when set and also
// returns extra.
type recordingInbox struct {
	*memstore.BackchannelInbox
	added, removed [][32]byte
	subjectKeys    []string
	extra          []storage.BackchannelInboxEntry
	listErr        error
}

func newRecordingInbox() *recordingInbox {
	return &recordingInbox{BackchannelInbox: memstore.NewBackchannelInbox()}
}

func (b *recordingInbox) AddBackchannelRequest(ctx context.Context, entry storage.NewBackchannelInboxEntry) error {
	b.added = append(b.added, entry.HandleHash)
	b.subjectKeys = append(b.subjectKeys, entry.SubjectKey)
	return b.BackchannelInbox.AddBackchannelRequest(ctx, entry)
}

func (b *recordingInbox) ListBackchannelRequests(ctx context.Context, listing storage.BackchannelInboxListing) ([]storage.BackchannelInboxEntry, error) {
	if b.listErr != nil {
		return nil, b.listErr
	}
	entries, err := b.BackchannelInbox.ListBackchannelRequests(ctx, listing)
	return append(entries, b.extra...), err
}

func (b *recordingInbox) RemoveBackchannelRequest(ctx context.Context, handleHash [32]byte) error {
	b.removed = append(b.removed, handleHash)
	return b.BackchannelInbox.RemoveBackchannelRequest(ctx, handleHash)
}

// held is how many entries the inbox holds under the subject key of the
// n-th entry it was asked to add, expired or not.
func (b *recordingInbox) held(t *testing.T, n int) int {
	t.Helper()
	entries, err := b.BackchannelInbox.ListBackchannelRequests(context.Background(), storage.BackchannelInboxListing{SubjectKey: b.subjectKeys[n]})
	if err != nil {
		t.Fatalf("ListBackchannelRequests: %v", err)
	}
	return len(entries)
}

// cibaClient is a registered CIBA client a test sends requests as.
type cibaClient struct {
	id  fapi.ClientID
	key *ecdsa.PrivateKey
}

// registerCIBAClient registers id, with a key of its own, as a CIBA
// client in the dependencies newHarnessWithBackchannelOptions builds.
func registerCIBAClient(t *testing.T, d *server.Dependencies, id fapi.ClientID) cibaClient {
	t.Helper()
	key := generateKey(t)
	client, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID:                       id,
		RedirectURIs:             []fapi.RegisteredRedirectURI{testRedirectURI},
		ClientAssertionAlgorithm: fapi.ES256,
		AllowedScopes:            []string{"openid", "accounts"},
		BackchannelAuthenticationRequestAlgorithm: fapi.ES256,
	})
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}
	d.Clients.(*fakeClientRepository).clients[id] = client
	d.ClientKeys.(*fakeClientKeySource).keysByClient[id] = []keys.VerificationKey{{Algorithm: fapi.ES256, PublicKey: &key.PublicKey}}
	return cibaClient{id: id, key: key}
}

// capsHarness is a CIBA harness over store, filing requests for user-1
// and user-2 in inbox, with Limits' caps on pending requests set to
// total and perClient (zero: the defaults). It returns testClientID's
// client first, then one for each of others, registered beside it.
func capsHarness(t *testing.T, store storage.BackchannelAuthenticationStore, inbox storage.BackchannelInbox, total, perClient int, others ...fapi.ClientID) (harness, []cibaClient) {
	t.Helper()
	var registered []cibaClient
	h := newHarnessWithBackchannelOptions(t, store, func(c *server.Config) {
		c.Limits.MaxPendingBackchannelAuthenticationRequests = total
		c.Limits.MaxPendingBackchannelAuthenticationRequestsPerClient = perClient
	}, func(d *server.Dependencies) {
		d.BackchannelSubjects = hintSubjects{known: map[string]bool{"user-1": true, "user-2": true}}
		d.BackchannelInbox = inbox
		for _, id := range others {
			registered = append(registered, registerCIBAClient(t, d, id))
		}
	})
	return h, append([]cibaClient{{id: testClientID, key: h.key}}, registered...)
}

// beginAs sends a CIBA request from c naming loginHint.
func beginAs(t *testing.T, h harness, c cibaClient, loginHint string) server.BackchannelAuthenticationAction {
	t.Helper()
	return beginInContext(t, context.Background(), h, c, loginHint)
}

// beginInContext is beginAs, with ctx as the request's context.
func beginInContext(t *testing.T, ctx context.Context, h harness, c cibaClient, loginHint string) server.BackchannelAuthenticationAction {
	t.Helper()
	params := standardBackchannelParams(t)
	params["login_hint"] = jsonRaw(t, loginHint)
	obj, err := requestobject.Create(requestobject.CreateParams{
		Signer: c.key, Algorithm: fapi.ES256,
		ClientID: c.id.String(), Audience: testIssuer,
		Now: h.now, Lifetime: 30 * time.Second, Parameters: params,
	})
	if err != nil {
		t.Fatalf("requestobject.Create: %v", err)
	}
	assertion, err := clientassertion.CreateAssertion(clientassertion.AssertionRequest{
		Signer: c.key, Algorithm: fapi.ES256,
		ClientID: c.id.String(), Audience: testIssuer,
		Now: h.now, Lifetime: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("CreateAssertion: %v", err)
	}
	action, err := h.server.BeginBackchannelAuthentication(ctx, server.BeginBackchannelAuthenticationRequest{
		HTTP: server.FormRequest{Parameters: backchannelFormParams(assertion, obj)},
	})
	if err != nil {
		t.Fatalf("BeginBackchannelAuthentication: %v", err)
	}
	return action
}

// requireFiled fails unless action is a request accepted for the user's
// decision.
func requireFiled(t *testing.T, action server.BackchannelAuthenticationAction, what string) server.BackchannelInteractionRequired {
	t.Helper()
	required, ok := action.(server.BackchannelInteractionRequired)
	if !ok {
		t.Fatalf("%s = %+v, want it accepted", what, action)
	}
	return required
}

// requireBackchannelRefusal fails unless action refuses the request
// with code and HTTP status.
func requireBackchannelRefusal(t *testing.T, action server.BackchannelAuthenticationAction, what string, code server.ErrorCode, status int) *server.Error {
	t.Helper()
	local, ok := action.(server.BackchannelAuthenticationLocalError)
	if !ok {
		t.Fatalf("%s = %+v, want it refused with %s", what, action, code)
	}
	if local.Error.Code() != code || local.Error.HTTPStatus() != status {
		t.Fatalf("%s refused with %s %d, want %s %d", what, local.Error.Code(), local.Error.HTTPStatus(), code, status)
	}
	return local.Error
}

// requireOverCap fails unless action refuses the request as one too many
// pending for its user: access_denied, HTTP 403 (CIBA Core §13).
func requireOverCap(t *testing.T, action server.BackchannelAuthenticationAction, what string) *server.Error {
	t.Helper()
	return requireBackchannelRefusal(t, action, what, server.ErrorAccessDenied, 403)
}

// TestBackchannelInboxCapsAClientsPendingRequests: a request that would
// leave its user more pending requests from its client than
// MaxPendingBackchannelAuthenticationRequestsPerClient is refused with
// access_denied, isn't stored, and leaves the inbox; another client, or
// another user, isn't affected.
func TestBackchannelInboxCapsAClientsPendingRequests(t *testing.T) {
	store := &countingBackchannelStore{BackchannelAuthenticationStore: memstore.NewBackchannelAuthenticationStore()}
	inbox := newRecordingInbox()
	h, clients := capsHarness(t, store, inbox, 0, 2, "client-2")
	client, other := clients[0], clients[1]

	requireFiled(t, beginAs(t, h, client, "user-1"), "the first request")
	requireFiled(t, beginAs(t, h, client, "user-1"), "the second request")
	refused := requireOverCap(t, beginAs(t, h, client, "user-1"), "the third request from the client")

	if store.created != 2 {
		t.Errorf("%d requests stored, want the 2 accepted", store.created)
	}
	if len(inbox.added) != 3 || len(inbox.removed) != 1 || inbox.removed[0] != inbox.added[2] {
		t.Fatalf("inbox asked to add %d and remove %d entries, want the refused one added and removed", len(inbox.added), len(inbox.removed))
	}
	if held := inbox.held(t, 2); held != 2 {
		t.Errorf("the inbox holds %d entries for user-1, want the 2 accepted", held)
	}
	if pending := inboxOf(t, h, "user-1"); len(pending) != 2 {
		t.Errorf("inbox of user-1 = %d requests, want 2", len(pending))
	}

	rec := httptest.NewRecorder()
	refused.WriteJSON(rec)
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || rec.Code != 403 || body.Error != "access_denied" {
		t.Errorf("refusal written as %d %s, want 403 access_denied", rec.Code, rec.Body.Bytes())
	}

	requireFiled(t, beginAs(t, h, other, "user-1"), "another client's request for user-1")
	requireFiled(t, beginAs(t, h, client, "user-2"), "the client's request for user-2")
}

// TestBackchannelInboxCapsAUsersPendingRequests: a request that would
// leave its user more pending requests, from every client together,
// than MaxPendingBackchannelAuthenticationRequests is refused, even from
// a client under its own cap.
func TestBackchannelInboxCapsAUsersPendingRequests(t *testing.T) {
	store := &countingBackchannelStore{BackchannelAuthenticationStore: memstore.NewBackchannelAuthenticationStore()}
	inbox := newRecordingInbox()
	h, clients := capsHarness(t, store, inbox, 3, 2, "client-2", "client-3")

	requireFiled(t, beginAs(t, h, clients[0], "user-1"), "the first client's first request")
	requireFiled(t, beginAs(t, h, clients[0], "user-1"), "the first client's second request")
	requireFiled(t, beginAs(t, h, clients[1], "user-1"), "the second client's request")
	requireOverCap(t, beginAs(t, h, clients[2], "user-1"), "the third client's request, a fourth for user-1")

	if store.created != 3 {
		t.Errorf("%d requests stored, want the 3 accepted", store.created)
	}
	if len(inbox.removed) != 1 || inbox.removed[0] != inbox.added[3] {
		t.Errorf("inbox asked to remove %d entries, want the refused one", len(inbox.removed))
	}
	requireFiled(t, beginAs(t, h, clients[2], "user-2"), "the third client's request for user-2")
}

// TestBackchannelInboxCapsCountPendingRequestsOnly: a request stops
// counting once it's decided, and an entry the inbox lists past its
// expiry doesn't count.
func TestBackchannelInboxCapsCountPendingRequestsOnly(t *testing.T) {
	inbox := newRecordingInbox()
	h, clients := capsHarness(t, memstore.NewBackchannelAuthenticationStore(), inbox, 0, 1)

	first := requireFiled(t, beginAs(t, h, clients[0], "user-1"), "the first request")
	requireOverCap(t, beginAs(t, h, clients[0], "user-1"), "a second request while the first is pending")
	if err := h.server.CompleteBackchannelAuthentication(context.Background(), server.CompleteBackchannelAuthenticationRequest{
		Handle: first.Handle, Result: server.Deny("declined"),
	}); err != nil {
		t.Fatalf("CompleteBackchannelAuthentication: %v", err)
	}
	second := requireFiled(t, beginAs(t, h, clients[0], "user-1"), "a request once the first is decided")
	if err := h.server.CompleteBackchannelAuthentication(context.Background(), server.CompleteBackchannelAuthenticationRequest{
		Handle: second.Handle, Result: server.Deny("declined"),
	}); err != nil {
		t.Fatalf("CompleteBackchannelAuthentication: %v", err)
	}

	handle := "an expired request's handle"
	expired := inboxEntry(t, h, testIssuer, "user-1", handle, sha256.Sum256([]byte(handle)))
	expired.ExpiresAt = h.now
	inbox.extra = []storage.BackchannelInboxEntry{expired}
	requireFiled(t, beginAs(t, h, clients[0], "user-1"), "a request beside an expired entry")
}

// TestBackchannelInboxCapsDefaults: with both caps left zero, a user may
// have 32 pending requests, at most 8 of them from one client.
func TestBackchannelInboxCapsDefaults(t *testing.T) {
	t.Run("per client", func(t *testing.T) {
		h, clients := capsHarness(t, memstore.NewBackchannelAuthenticationStore(), newRecordingInbox(), 0, 0)
		for i := range 8 {
			requireFiled(t, beginAs(t, h, clients[0], "user-1"), fmt.Sprintf("request %d", i+1))
		}
		requireOverCap(t, beginAs(t, h, clients[0], "user-1"), "a ninth request from the client")
	})
	t.Run("per user", func(t *testing.T) {
		inbox := newRecordingInbox()
		h, clients := capsHarness(t, memstore.NewBackchannelAuthenticationStore(), inbox, 0, 0)
		for i := range 31 {
			handle := fmt.Sprintf("another client's request %d", i)
			entry := inboxEntry(t, h, testIssuer, "user-1", handle, sha256.Sum256([]byte(handle)))
			entry.ClientID = fapi.ClientID(fmt.Sprintf("client-%d", i%4))
			inbox.extra = append(inbox.extra, entry)
		}
		requireFiled(t, beginAs(t, h, clients[0], "user-1"), "a 32nd request for user-1")
		requireOverCap(t, beginAs(t, h, clients[0], "user-1"), "a 33rd request for user-1")
	})
}

// TestRecommendedLimitsSetThePendingRequestCaps: RecommendedLimits names
// the defaults a zero cap means.
func TestRecommendedLimitsSetThePendingRequestCaps(t *testing.T) {
	limits := server.RecommendedLimits()
	if limits.MaxPendingBackchannelAuthenticationRequests != 32 || limits.MaxPendingBackchannelAuthenticationRequestsPerClient != 8 {
		t.Fatalf("RecommendedLimits() caps = %d, %d per client, want 32, 8", limits.MaxPendingBackchannelAuthenticationRequests, limits.MaxPendingBackchannelAuthenticationRequestsPerClient)
	}
}

// TestBackchannelCapsNeedAnInbox: without a BackchannelInbox there is
// nothing to count, and no cap applies.
func TestBackchannelCapsNeedAnInbox(t *testing.T) {
	h := newHarnessWithBackchannelOptions(t, memstore.NewBackchannelAuthenticationStore(), func(c *server.Config) {
		c.Limits.MaxPendingBackchannelAuthenticationRequests = 1
		c.Limits.MaxPendingBackchannelAuthenticationRequestsPerClient = 1
	}, func(d *server.Dependencies) {
		d.BackchannelSubjects = hintSubjects{known: map[string]bool{"user-1": true}}
	})
	for i := range 3 {
		requireFiled(t, beginForInbox(t, h, "user-1"), fmt.Sprintf("request %d without an inbox", i+1))
	}
}

// TestBackchannelInboxCapsFailClosed: an inbox that can't list the
// user's requests once the new one is filed refuses it as a filing
// failure: server_error, nothing stored, and the entry taken out again.
func TestBackchannelInboxCapsFailClosed(t *testing.T) {
	store := &countingBackchannelStore{BackchannelAuthenticationStore: memstore.NewBackchannelAuthenticationStore()}
	inbox := newRecordingInbox()
	inbox.listErr = fmt.Errorf("db: %w", storage.ErrStoreUnavailable)
	h, clients := capsHarness(t, store, inbox, 0, 0)

	refused := requireBackchannelRefusal(t, beginAs(t, h, clients[0], "user-1"), "a request its user's inbox can't count", server.ErrorServerError, 500)
	if !errors.Is(refused, storage.ErrStoreUnavailable) || !strings.Contains(refused.PublicDescription(), "inbox") {
		t.Errorf("refusal = %v (%q), want the inbox's failure", refused, refused.PublicDescription())
	}
	if store.created != 0 {
		t.Errorf("%d requests stored, want none", store.created)
	}
	if len(inbox.added) != 1 || len(inbox.removed) != 1 || inbox.removed[0] != inbox.added[0] {
		t.Errorf("inbox asked to add %d and remove %d entries, want the refused one added and removed", len(inbox.added), len(inbox.removed))
	}
}

// failingCreateStore can't store any request.
type failingCreateStore struct {
	storage.BackchannelAuthenticationStore
}

func (failingCreateStore) CreateBackchannelAuthentication(context.Context, storage.NewBackchannelAuthentication) error {
	return fmt.Errorf("db: %w", storage.ErrStoreUnavailable)
}

// TestBackchannelInboxUnfilesARequestNotStored: a request filed in its
// user's inbox that the backchannel store then can't take is refused
// with server_error and taken out of the inbox, so it doesn't count
// against the caps.
func TestBackchannelInboxUnfilesARequestNotStored(t *testing.T) {
	inbox := newRecordingInbox()
	h, clients := capsHarness(t, failingCreateStore{memstore.NewBackchannelAuthenticationStore()}, inbox, 0, 0)

	refused := requireBackchannelRefusal(t, beginAs(t, h, clients[0], "user-1"), "a request the store can't take", server.ErrorServerError, 500)
	if !errors.Is(refused, storage.ErrStoreUnavailable) {
		t.Errorf("refusal = %v, want the store's failure", refused)
	}
	if len(inbox.added) != 1 || len(inbox.removed) != 1 || inbox.removed[0] != inbox.added[0] {
		t.Fatalf("inbox asked to add %d and remove %d entries, want the refused one added and removed", len(inbox.added), len(inbox.removed))
	}
	if held := inbox.held(t, 0); held != 0 {
		t.Errorf("the inbox holds %d entries for user-1, want none", held)
	}
}

// hangingUpInbox is a recordingInbox that, as a database does, fails
// every call once its context has ended, and that ends the request's
// context with hangUp, when set, as a client hanging up does: while a
// filing is being sent (at "send"), once it has kept one (at "add"), or
// once it has listed the requests pending (at "list"). A filing whose
// context ends while it's being sent is reported failed at once, but
// lands only after the inbox's next call: a database client can return
// as soon as its context ends, while the database goes on to commit the
// write it was sent. With failKept, it reports the filing it
// kept at "add" as failed, as a store can report a commit that landed.
// unbounded counts the filings and removals asked for without a
// deadline.
type hangingUpInbox struct {
	*recordingInbox
	hangUp    context.CancelFunc
	after     string
	failKept  bool
	sent      []storage.NewBackchannelInboxEntry
	unbounded int
}

func (b *hangingUpInbox) AddBackchannelRequest(ctx context.Context, entry storage.NewBackchannelInboxEntry) error {
	defer b.commit(b.uncommitted())
	if err := b.startWrite(ctx); err != nil {
		return err
	}
	if b.hangUp != nil && b.after == "send" {
		b.hangUp()
		if err := ctx.Err(); err != nil {
			b.sent = append(b.sent, entry)
			return fmt.Errorf("db: %w", err)
		}
	}
	if err := b.recordingInbox.AddBackchannelRequest(ctx, entry); err != nil {
		return err
	}
	if b.hangUp != nil && b.after == "add" {
		b.hangUp()
		if b.failKept {
			return fmt.Errorf("db: commit: %w", storage.ErrStoreUnavailable)
		}
	}
	return nil
}

func (b *hangingUpInbox) ListBackchannelRequests(ctx context.Context, listing storage.BackchannelInboxListing) ([]storage.BackchannelInboxEntry, error) {
	defer b.commit(b.uncommitted())
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	entries, err := b.recordingInbox.ListBackchannelRequests(ctx, listing)
	if b.hangUp != nil && b.after == "list" {
		b.hangUp()
	}
	return entries, err
}

func (b *hangingUpInbox) RemoveBackchannelRequest(ctx context.Context, handleHash [32]byte) error {
	defer b.commit(b.uncommitted())
	if err := b.startWrite(ctx); err != nil {
		return err
	}
	return b.recordingInbox.RemoveBackchannelRequest(ctx, handleHash)
}

// startWrite fails a filing or a removal whose context has ended, and
// counts one with no deadline.
func (b *hangingUpInbox) startWrite(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, bounded := ctx.Deadline(); !bounded {
		b.unbounded++
	}
	return nil
}

// uncommitted takes the filings sent before this call that the database
// has yet to commit.
func (b *hangingUpInbox) uncommitted() []storage.NewBackchannelInboxEntry {
	sent := b.sent
	b.sent = nil
	return sent
}

// commit lands sent, as the database goes on to commit them.
func (b *hangingUpInbox) commit(sent []storage.NewBackchannelInboxEntry) {
	for _, entry := range sent {
		_ = b.recordingInbox.AddBackchannelRequest(context.Background(), entry) // memstore's never fails
	}
}

// hangUpAwareStore is a backchannel store that, as a database does,
// can't store a request once its context has ended.
type hangUpAwareStore struct {
	storage.BackchannelAuthenticationStore
}

func (s hangUpAwareStore) CreateBackchannelAuthentication(ctx context.Context, record storage.NewBackchannelAuthentication) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("db: %w", err)
	}
	return s.BackchannelAuthenticationStore.CreateBackchannelAuthentication(ctx, record)
}

// TestBackchannelInboxUnfilesARequestWhoseClientHungUp: a request
// refused or not stored leaves its user's inbox even when its client
// hangs up meanwhile, ending the request's context: even when the inbox
// reports a filing it kept as failed, and even when its database would
// commit a filing whose context had ended only after its removal had
// run. Otherwise one client, its requests refused over and over, could
// leave enough entries behind to take its user past the cap on pending
// requests for every client.
func TestBackchannelInboxUnfilesARequestWhoseClientHungUp(t *testing.T) {
	for _, tc := range []struct {
		name     string
		after    string // when the client hangs up: "send", "add" or "list"
		failKept bool
		accepted int // the client's requests accepted first
		code     server.ErrorCode
		status   int
	}{
		{name: "as the filing is sent", after: "send", code: server.ErrorServerError, status: 500},
		{name: "once filed", after: "add", code: server.ErrorServerError, status: 500},
		{name: "once filed, the filing reported failed", after: "add", failKept: true, code: server.ErrorServerError, status: 500},
		{name: "once counted, past its cap", after: "list", accepted: 8, code: server.ErrorAccessDenied, status: 403},
		{name: "once counted, before it's stored", after: "list", code: server.ErrorServerError, status: 500},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inbox := &hangingUpInbox{recordingInbox: newRecordingInbox(), after: tc.after, failKept: tc.failKept}
			h, clients := capsHarness(t, hangUpAwareStore{memstore.NewBackchannelAuthenticationStore()}, inbox, 0, 0, "client-2")
			for i := range tc.accepted {
				requireFiled(t, beginAs(t, h, clients[0], "user-1"), fmt.Sprintf("request %d", i+1))
			}
			// More than the cap on a user's pending requests, so that
			// entries left behind would refuse every other client too.
			for i := range 40 {
				ctx, cancel := context.WithCancel(context.Background())
				inbox.hangUp = cancel
				requireBackchannelRefusal(t, beginInContext(t, ctx, h, clients[0], "user-1"), fmt.Sprintf("request %d, its client hanging up %s", tc.accepted+i+1, tc.name), tc.code, tc.status)
				inbox.hangUp = nil
				cancel()
			}

			if held := inbox.held(t, 0); held != tc.accepted {
				t.Errorf("the inbox holds %d entries for user-1, want only the %d accepted", held, tc.accepted)
			}
			if inbox.unbounded != 0 {
				t.Errorf("%d filings and removals had no deadline, want each bounded", inbox.unbounded)
			}
			requireFiled(t, beginAs(t, h, clients[1], "user-1"), "another client's request for user-1")
		})
	}
}

// TestNewRefusesNegativePendingRequestCaps: neither cap may be negative,
// whether or not CIBA is enabled; zero, the default, is accepted.
func TestNewRefusesNegativePendingRequestCaps(t *testing.T) {
	ciba := newHarnessWithBackchannelOptions(t, memstore.NewBackchannelAuthenticationStore(), nil, nil)
	for name, configs := range map[string]struct {
		cfg  server.Config
		deps server.Dependencies
	}{
		"CIBA enabled":  {ciba.cfg, ciba.deps},
		"CIBA disabled": {validConfig(t), validDependencies()},
	} {
		for field, mutate := range map[string]func(*server.Limits){
			"max_pending_backchannel_authentication_requests":            func(l *server.Limits) { l.MaxPendingBackchannelAuthenticationRequests = -1 },
			"max_pending_backchannel_authentication_requests_per_client": func(l *server.Limits) { l.MaxPendingBackchannelAuthenticationRequestsPerClient = -1 },
		} {
			t.Run(name+"/"+field, func(t *testing.T) {
				cfg := configs.cfg
				mutate(&cfg.Limits)
				if _, err := server.New(cfg, configs.deps); err == nil || !strings.Contains(err.Error(), "limits."+field+" must not be negative") {
					t.Fatalf("New(negative %s) = %v, want it refused", field, err)
				}
			})
		}
		t.Run(name+"/zero", func(t *testing.T) {
			cfg := configs.cfg
			cfg.Limits.MaxPendingBackchannelAuthenticationRequests = 0
			cfg.Limits.MaxPendingBackchannelAuthenticationRequestsPerClient = 0
			if _, err := server.New(cfg, configs.deps); err != nil {
				t.Fatalf("New(zero caps): %v", err)
			}
		})
	}
}

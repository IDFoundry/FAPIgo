package server_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// hintSubjects resolves a login_hint to the subject of the same name,
// for the hints it knows.
type hintSubjects struct{ known map[string]bool }

func (r hintSubjects) ResolveBackchannelSubject(_ context.Context, _ fapi.ClientID, hints server.BackchannelAuthenticationHints) (server.SubjectID, error) {
	if !r.known[string(hints.LoginHint)] {
		return server.SubjectID{}, fmt.Errorf("no customer %q: %w", hints.LoginHint, server.ErrUnknownUserID)
	}
	return server.NewSubjectID(string(hints.LoginHint))
}

func inboxHarness(t *testing.T, inbox storage.BackchannelInbox) harness {
	t.Helper()
	return newHarnessWithBackchannelOptions(t, memstore.NewBackchannelAuthenticationStore(), nil, func(d *server.Dependencies) {
		d.BackchannelSubjects = hintSubjects{known: map[string]bool{"user-1": true, "user-2": true}}
		d.BackchannelInbox = inbox
	})
}

func beginForInbox(t *testing.T, h harness, loginHint string) server.BackchannelAuthenticationAction {
	t.Helper()
	params := standardBackchannelParams(t)
	params["login_hint"] = jsonRaw(t, loginHint)
	action, err := h.server.BeginBackchannelAuthentication(context.Background(), server.BeginBackchannelAuthenticationRequest{
		HTTP: server.FormRequest{Parameters: backchannelFormParams(h.clientAssertion(t), h.backchannelRequestObject(t, params))},
	})
	if err != nil {
		t.Fatalf("BeginBackchannelAuthentication: %v", err)
	}
	return action
}

func beginFiled(t *testing.T, h harness, loginHint string) server.BackchannelInteractionRequired {
	t.Helper()
	required, ok := beginForInbox(t, h, loginHint).(server.BackchannelInteractionRequired)
	if !ok {
		t.Fatal("BeginBackchannelAuthentication didn't require an interaction")
	}
	return required
}

func inboxOf(t *testing.T, h harness, subject string) []server.PendingBackchannelInteraction {
	t.Helper()
	pending, err := h.server.ListBackchannelInteractions(context.Background(), mustSubjectID(t, subject))
	if err != nil {
		t.Fatalf("ListBackchannelInteractions(%s): %v", subject, err)
	}
	return pending
}

func approveAs(t *testing.T, h harness, handle server.BackchannelAuthenticationHandle, scope []string, subject string) {
	t.Helper()
	authenticated, err := server.NewAuthenticatedSubject(mustSubjectID(t, subject))
	if err != nil {
		t.Fatal(err)
	}
	authCtx, err := server.NewAuthenticationContext(h.now, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.server.CompleteBackchannelAuthentication(context.Background(), server.CompleteBackchannelAuthenticationRequest{
		Handle: handle,
		Result: server.Authorize(authenticated, authCtx, server.GrantedAuthorization{Scope: scope}),
	}); err != nil {
		t.Fatalf("CompleteBackchannelAuthentication: %v", err)
	}
}

// TestBackchannelInboxListsTheHintedUsersRequests: a request is filed
// under the user its hint names, with what BeginBackchannelAuthentication
// returned, and leaves the inbox once decided.
func TestBackchannelInboxListsTheHintedUsersRequests(t *testing.T) {
	h := inboxHarness(t, memstore.NewBackchannelInbox())
	required := beginFiled(t, h, "user-1")

	pending := inboxOf(t, h, "user-1")
	if len(pending) != 1 {
		t.Fatalf("inbox of user-1 = %d requests, want 1", len(pending))
	}
	if pending[0].Handle.String() != required.Handle.String() {
		t.Error("the listed handle isn't the request's")
	}
	if id := pending[0].ID; id == "" || strings.Contains(id, required.Handle.String()) {
		t.Errorf("listed ID = %q, want a non-empty ID that isn't the handle", id)
	}
	if !reflect.DeepEqual(pending[0].Interaction, required.Interaction) {
		t.Errorf("listed interaction = %+v, want %+v", pending[0].Interaction, required.Interaction)
	}
	if others := inboxOf(t, h, "user-2"); len(others) != 0 {
		t.Errorf("inbox of user-2 = %d requests, want none", len(others))
	}

	approveAs(t, h, pending[0].Handle, pending[0].Interaction.Scope, "user-1")
	if left := inboxOf(t, h, "user-1"); len(left) != 0 {
		t.Errorf("inbox after the decision = %d requests, want none", len(left))
	}
	if _, err := exchangeCIBA(t, h, required.AuthReqID.String()); err != nil {
		t.Errorf("token request after approval: %v", err)
	}
}

// TestBackchannelSubjectsBindTheRequest: only the user the hint named
// may approve; anyone else's approval is a failed authentication.
func TestBackchannelSubjectsBindTheRequest(t *testing.T) {
	h := inboxHarness(t, memstore.NewBackchannelInbox())
	required := beginFiled(t, h, "user-1")
	approveAs(t, h, required.Handle, required.Interaction.Scope, "user-2")
	if _, err := exchangeCIBA(t, h, required.AuthReqID.String()); serverErrorCode(t, err) != server.ErrorAccessDenied {
		t.Errorf("token request after another user's approval = %v, want access_denied", err)
	}
}

// TestBackchannelSubjectsRefuseUnknownHints: a hint the resolver can't
// resolve is refused with unknown_user_id, and nothing is filed.
func TestBackchannelSubjectsRefuseUnknownHints(t *testing.T) {
	h := inboxHarness(t, memstore.NewBackchannelInbox())
	local, ok := beginForInbox(t, h, "nobody").(server.BackchannelAuthenticationLocalError)
	if !ok || local.Error.Code() != server.ErrorUnknownUserID {
		t.Fatalf("begin with an unknown hint = %+v, want unknown_user_id", local)
	}
}

// failingInbox fails every AddBackchannelRequest.
type failingInbox struct{ *memstore.BackchannelInbox }

func (failingInbox) AddBackchannelRequest(context.Context, storage.NewBackchannelInboxEntry) error {
	return errors.New("inbox down")
}

// TestBackchannelInboxFilingFailureRefusesTheRequest: a request its
// user's inbox couldn't take isn't stored, so none is pending unseen.
func TestBackchannelInboxFilingFailureRefusesTheRequest(t *testing.T) {
	h := inboxHarness(t, failingInbox{memstore.NewBackchannelInbox()})
	local, ok := beginForInbox(t, h, "user-1").(server.BackchannelAuthenticationLocalError)
	if !ok || local.Error.Code() != server.ErrorServerError {
		t.Fatalf("begin with the inbox down = %+v, want server_error", local)
	}
}

func TestBackchannelInboxNeedsSubjects(t *testing.T) {
	h := newHarnessWithBackchannelOptions(t, memstore.NewBackchannelAuthenticationStore(), nil, nil)
	deps := h.deps
	deps.BackchannelInbox = memstore.NewBackchannelInbox()
	if _, err := server.New(h.cfg, deps); err == nil || !strings.Contains(err.Error(), "backchannel subjects") {
		t.Errorf("New(inbox, no subjects) = %v, want it to name backchannel subjects", err)
	}
	if _, err := h.server.ListBackchannelInteractions(context.Background(), mustSubjectID(t, "user-1")); err == nil || !strings.Contains(err.Error(), "Dependencies.BackchannelInbox") {
		t.Errorf("ListBackchannelInteractions without an inbox = %v, want it to name the dependency", err)
	}
}

// declaredInbox is a BackchannelInbox declaring caps.
type declaredInbox struct {
	*memstore.BackchannelInbox
	caps storage.Capabilities
}

func (b declaredInbox) Capabilities() storage.Capabilities { return b.caps }

func TestProductionChecksBackchannelInbox(t *testing.T) {
	for name, tc := range map[string]struct {
		inbox storage.BackchannelInbox
		want  string
	}{
		"memstore":    {memstore.NewBackchannelInbox(), "backchannel_inbox must implement storage.StoreAssurance"},
		"not durable": {declaredInbox{memstore.NewBackchannelInbox(), storage.Capabilities{}}, "backchannel_inbox must declare Durable"},
	} {
		t.Run(name, func(t *testing.T) {
			err := productionCIBANew(t, func(deps *server.Dependencies) {
				deps.BackchannelSubjects = hintSubjects{}
				deps.BackchannelInbox = tc.inbox
			})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("New(production, %s inbox) = %v, want %q", name, err, tc.want)
			}
		})
	}
}

// productionCIBANew builds a production server with CIBA enabled, after
// mutate, and returns New's error. New reports every refusal at once, so
// a test matches the one it's about among any others.
func productionCIBANew(t *testing.T, mutate func(*server.Dependencies)) error {
	t.Helper()
	cfg := validConfig(t)
	asProduction(&cfg)
	cfg.Deployment = server.DeploymentSingleInstance
	backchannelEndpoint, err := fapi.ParseEndpointURL(testBackchannelAuthenticationEndpoint)
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	cfg.Endpoints.BackchannelAuthentication = backchannelEndpoint
	cfg.Algorithms.BackchannelAuthenticationRequest = server.AlgorithmSet{fapi.ES256}
	cfg.Limits.BackchannelAuthenticationRequestLifetime = 2 * time.Minute
	cfg.Limits.MaxBackchannelAuthenticationRequestLifetime = time.Minute
	cfg.Limits.BackchannelAuthenticationPollInterval = time.Second
	deps := validDependencies()
	deps.Audit = &fakeAuditSink{}
	deps.Backchannel = memstore.NewBackchannelAuthenticationStore()
	deps.BackchannelNotifier = server.NoBackchannelNotifications{}
	mutate(&deps)
	_, err = server.New(cfg, deps)
	return err
}

// stubInbox lists memstore's entries plus extra, or fails with listErr.
type stubInbox struct {
	*memstore.BackchannelInbox
	extra   []storage.BackchannelInboxEntry
	listErr error
}

func (b *stubInbox) ListBackchannelRequests(ctx context.Context, listing storage.BackchannelInboxListing) ([]storage.BackchannelInboxEntry, error) {
	if b.listErr != nil {
		return nil, b.listErr
	}
	entries, err := b.BackchannelInbox.ListBackchannelRequests(ctx, listing)
	return append(entries, b.extra...), err
}

// inboxEntry is a BackchannelInboxEntry holding record fields as the
// server writes them, for handle, expiring in an hour unless changed.
func inboxEntry(t *testing.T, h harness, issuer, subject, handle string, hash [32]byte) storage.BackchannelInboxEntry {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"v": 1, "iss": issuer, "handle": handle, "sub": subject})
	if err != nil {
		t.Fatal(err)
	}
	return storage.BackchannelInboxEntry{HandleHash: hash, ClientID: testClientID, Record: raw, ExpiresAt: h.now.Add(time.Hour)}
}

// TestListBackchannelInteractionsReadsEntries: requests are listed
// soonest to expire first, and an entry that isn't a live request of the
// subject's at this server is left out: another issuer's, another
// subject's, expired, with a handle that doesn't match its key or
// doesn't parse, or naming a request the store doesn't hold.
func TestListBackchannelInteractionsReadsEntries(t *testing.T) {
	inbox := &stubInbox{BackchannelInbox: memstore.NewBackchannelInbox()}
	h := inboxHarness(t, inbox)
	first := beginFiled(t, h, "user-1")
	second := beginFiled(t, h, "user-1")
	handle := first.Handle.String()
	hash := sha256.Sum256([]byte(handle))
	expired := inboxEntry(t, h, testIssuer, "user-1", handle, hash)
	expired.ExpiresAt = h.now
	unknown := "never-begun-handle"
	inbox.extra = []storage.BackchannelInboxEntry{
		inboxEntry(t, h, "https://other-as.example", "user-1", handle, hash),
		inboxEntry(t, h, testIssuer, "user-2", handle, hash),
		expired,
		inboxEntry(t, h, testIssuer, "user-1", handle, sha256.Sum256([]byte("another handle"))),
		inboxEntry(t, h, testIssuer, "user-1", "", sha256.Sum256(nil)),
		inboxEntry(t, h, testIssuer, "user-1", unknown, sha256.Sum256([]byte(unknown))),
	}
	pending := inboxOf(t, h, "user-1")
	if len(pending) != 2 {
		t.Fatalf("inbox of user-1 = %d requests, want the 2 begun", len(pending))
	}
	got := map[string]bool{pending[0].Handle.String(): true, pending[1].Handle.String(): true}
	if !got[first.Handle.String()] || !got[second.Handle.String()] {
		t.Error("the inbox doesn't list the two begun requests")
	}
	if pending[0].ExpiresAt.After(pending[1].ExpiresAt) {
		t.Error("the inbox isn't soonest to expire first")
	}
}

// TestListBackchannelInteractionsFails: a store or record it can't read,
// a client it can't resolve, or no subject fails the listing rather than
// hiding a request.
func TestListBackchannelInteractionsFails(t *testing.T) {
	t.Run("store can't answer", func(t *testing.T) {
		h := inboxHarness(t, &stubInbox{BackchannelInbox: memstore.NewBackchannelInbox(), listErr: errors.New("inbox down")})
		if _, err := h.server.ListBackchannelInteractions(context.Background(), mustSubjectID(t, "user-1")); err == nil {
			t.Fatal("ListBackchannelInteractions = nil error, want error")
		}
	})
	t.Run("undecodable entry", func(t *testing.T) {
		inbox := &stubInbox{BackchannelInbox: memstore.NewBackchannelInbox()}
		h := inboxHarness(t, inbox)
		inbox.extra = []storage.BackchannelInboxEntry{{Record: json.RawMessage(`{`), ExpiresAt: h.now.Add(time.Hour)}}
		if _, err := h.server.ListBackchannelInteractions(context.Background(), mustSubjectID(t, "user-1")); err == nil {
			t.Fatal("ListBackchannelInteractions = nil error, want error")
		}
	})
	t.Run("client store can't answer", func(t *testing.T) {
		h := inboxHarness(t, memstore.NewBackchannelInbox())
		beginFiled(t, h, "user-1")
		h.clients.err = fmt.Errorf("db: %w", storage.ErrStoreUnavailable)
		if _, err := h.server.ListBackchannelInteractions(context.Background(), mustSubjectID(t, "user-1")); err == nil {
			t.Fatal("ListBackchannelInteractions = nil error, want error")
		}
	})
	t.Run("no subject", func(t *testing.T) {
		h := inboxHarness(t, memstore.NewBackchannelInbox())
		if _, err := h.server.ListBackchannelInteractions(context.Background(), server.SubjectID{}); err == nil {
			t.Fatal("ListBackchannelInteractions(zero SubjectID) = nil error, want error")
		}
	})
}

// emptySubjects resolves every hint to no subject, breaking its contract.
type emptySubjects struct{}

func (emptySubjects) ResolveBackchannelSubject(context.Context, fapi.ClientID, server.BackchannelAuthenticationHints) (server.SubjectID, error) {
	return server.SubjectID{}, nil
}

func TestBackchannelSubjectsMustNameSomeone(t *testing.T) {
	h := newHarnessWithBackchannelOptions(t, memstore.NewBackchannelAuthenticationStore(), nil, func(d *server.Dependencies) {
		d.BackchannelSubjects = emptySubjects{}
	})
	local, ok := beginForInbox(t, h, "user-1").(server.BackchannelAuthenticationLocalError)
	if !ok || local.Error.Code() != server.ErrorServerError {
		t.Fatalf("begin with a resolver naming nobody = %+v, want server_error", local)
	}
}

// TestDenyBackchannelInteractions denies every request awaiting one
// user, and none of another's.
func TestDenyBackchannelInteractions(t *testing.T) {
	h := inboxHarness(t, memstore.NewBackchannelInbox())
	first := beginFiled(t, h, "user-1")
	second := beginFiled(t, h, "user-1")
	other := beginFiled(t, h, "user-2")

	n, err := h.server.DenyBackchannelInteractions(context.Background(), mustSubjectID(t, "user-1"), "the account was closed")
	if err != nil || n != 2 {
		t.Fatalf("DenyBackchannelInteractions(user-1) = %d, %v, want 2", n, err)
	}
	for _, req := range []server.BackchannelInteractionRequired{first, second} {
		if _, err := exchangeCIBA(t, h, req.AuthReqID.String()); serverErrorCode(t, err) != server.ErrorAccessDenied {
			t.Errorf("token request for a denied request = %v, want access_denied", err)
		}
	}
	if left := inboxOf(t, h, "user-1"); len(left) != 0 {
		t.Errorf("inbox of user-1 after = %d requests, want none", len(left))
	}
	if left := inboxOf(t, h, "user-2"); len(left) != 1 || left[0].Handle.String() != other.Handle.String() {
		t.Errorf("inbox of user-2 = %d requests, want its one left alone", len(left))
	}
}

// staleInbox lists a request after it has been decided, as an inbox
// whose removal failed would.
type staleInbox struct{ *memstore.BackchannelInbox }

func (staleInbox) RemoveBackchannelRequest(context.Context, [32]byte) error {
	return errors.New("inbox down")
}

// TestDenyBackchannelInteractionsPassesOverDecided: a request decided
// since it was listed is passed over, not an error.
func TestDenyBackchannelInteractionsPassesOverDecided(t *testing.T) {
	h := inboxHarness(t, staleInbox{memstore.NewBackchannelInbox()})
	required := beginFiled(t, h, "user-1")
	approveAs(t, h, required.Handle, required.Interaction.Scope, "user-1")
	if n, err := h.server.DenyBackchannelInteractions(context.Background(), mustSubjectID(t, "user-1"), "closed"); err != nil || n != 0 {
		t.Fatalf("DenyBackchannelInteractions(only a decided request) = %d, %v, want 0, nil", n, err)
	}
}

// TestDenyBackchannelInteractionsReportsFailures: an inbox it can't read
// fails at once.
func TestDenyBackchannelInteractionsReportsFailures(t *testing.T) {
	t.Run("list", func(t *testing.T) {
		h := inboxHarness(t, &stubInbox{BackchannelInbox: memstore.NewBackchannelInbox(), listErr: errors.New("inbox down")})
		if n, err := h.server.DenyBackchannelInteractions(context.Background(), mustSubjectID(t, "user-1"), "closed"); err == nil || n != 0 {
			t.Fatalf("DenyBackchannelInteractions = %d, %v, want 0 and an error", n, err)
		}
	})
}

// corruptOnSecondLookup returns a record that won't decode from its
// second lookup on: the listing reads the request, and the denial then
// finds it unreadable.
type corruptOnSecondLookup struct {
	storage.BackchannelAuthenticationStore
	lookups int
}

func (s *corruptOnSecondLookup) LookupBackchannelAuthentication(ctx context.Context, handleHash [32]byte) (storage.LookedUpBackchannelAuthentication, error) {
	s.lookups++
	found, err := s.BackchannelAuthenticationStore.LookupBackchannelAuthentication(ctx, handleHash)
	if s.lookups > 1 && err == nil {
		found.Request = json.RawMessage(`{`)
	}
	return found, err
}

// TestDenyBackchannelInteractionsStopsAtAFailure: a denial that fails
// for anything but the request having been decided or expired stops
// it, with the error.
func TestDenyBackchannelInteractionsStopsAtAFailure(t *testing.T) {
	store := &corruptOnSecondLookup{BackchannelAuthenticationStore: memstore.NewBackchannelAuthenticationStore()}
	h := newHarnessWithBackchannelOptions(t, store, nil, func(d *server.Dependencies) {
		d.BackchannelSubjects = hintSubjects{known: map[string]bool{"user-1": true}}
		d.BackchannelInbox = memstore.NewBackchannelInbox()
	})
	beginFiled(t, h, "user-1")
	if n, err := h.server.DenyBackchannelInteractions(context.Background(), mustSubjectID(t, "user-1"), "closed"); err == nil || n != 0 {
		t.Fatalf("DenyBackchannelInteractions(unreadable record) = %d, %v, want 0 and an error", n, err)
	}
}

// fixedSubjects resolves every hint to subject.
type fixedSubjects struct{ subject string }

func (r fixedSubjects) ResolveBackchannelSubject(context.Context, fapi.ClientID, server.BackchannelAuthenticationHints) (server.SubjectID, error) {
	return server.NewSubjectID(r.subject)
}

// beginWithIDTokenHint begins a CIBA request at h whose id_token_hint
// names sub, with Dependencies.BackchannelSubjects resolving every hint
// to resolved.
func beginWithIDTokenHint(t *testing.T, h harness, sub, resolved string) server.BackchannelAuthenticationAction {
	t.Helper()
	params := standardBackchannelParams(t)
	delete(params, "login_hint")
	params["id_token_hint"] = jsonRaw(t, serverHint(t, h, func(c map[string]any) { c["sub"] = sub }))
	h.deps.BackchannelSubjects = fixedSubjects{subject: resolved}
	srv, err := server.New(h.cfg, h.deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h.server = srv
	action, err := h.server.BeginBackchannelAuthentication(context.Background(), server.BeginBackchannelAuthenticationRequest{
		HTTP: server.FormRequest{Parameters: backchannelFormParams(h.clientAssertion(t), h.backchannelRequestObject(t, params))},
	})
	if err != nil {
		t.Fatalf("BeginBackchannelAuthentication: %v", err)
	}
	return action
}

// TestBackchannelSubjectsMustAgreeWithTheIDTokenHint: when the server
// can tell which user an id_token_hint names (a public client's sub is
// the internal subject; a pairwise one it can map back), a resolver
// naming someone else is a misconfiguration, refused rather than letting
// the resolver's user approve.
func TestBackchannelSubjectsMustAgreeWithTheIDTokenHint(t *testing.T) {
	t.Run("pairwise", func(t *testing.T) {
		h := cibaWithPairwise(t, newMappingDeriver())
		action := beginWithIDTokenHint(t, h, clientSubjectOf(t, h, "user-1"), "user-2")
		if local, ok := action.(server.BackchannelAuthenticationLocalError); !ok || local.Error.Code() != server.ErrorServerError {
			t.Fatalf("begin with a resolver disagreeing with the id_token_hint = %+v, want server_error", action)
		}
	})
	t.Run("public", func(t *testing.T) {
		h, _ := newHarnessWithBackchannel(t)
		action := beginWithIDTokenHint(t, h, "user-1", "user-2")
		if local, ok := action.(server.BackchannelAuthenticationLocalError); !ok || local.Error.Code() != server.ErrorServerError {
			t.Fatalf("begin with a resolver disagreeing with the id_token_hint = %+v, want server_error", action)
		}
	})
	t.Run("public, agreeing", func(t *testing.T) {
		h, _ := newHarnessWithBackchannel(t)
		required, ok := beginWithIDTokenHint(t, h, "user-1", "user-1").(server.BackchannelInteractionRequired)
		if !ok || required.Interaction.RequiredSubject != "user-1" {
			t.Fatalf("begin with a resolver agreeing with the id_token_hint = %+v, want an interaction for user-1", required)
		}
	})
}

// TestBackchannelInboxSkipsADeregisteredClient: a request from a client
// no longer registered leaves the listing, rather than failing it for
// every request the user has.
func TestBackchannelInboxSkipsADeregisteredClient(t *testing.T) {
	h := inboxHarness(t, memstore.NewBackchannelInbox())
	beginFiled(t, h, "user-1")
	delete(h.clients.clients, testClientID)
	if pending := inboxOf(t, h, "user-1"); len(pending) != 0 {
		t.Errorf("inbox with the client deregistered = %d requests, want none", len(pending))
	}
	if n, err := h.server.DenyBackchannelInteractions(context.Background(), mustSubjectID(t, "user-1"), "closed"); err != nil || n != 0 {
		t.Errorf("DenyBackchannelInteractions = %d, %v, want 0, nil", n, err)
	}
}

// outageBackchannelStore fails lookups as an outage while down is set.
type outageBackchannelStore struct {
	storage.BackchannelAuthenticationStore
	down *bool
}

func (s outageBackchannelStore) LookupBackchannelAuthentication(ctx context.Context, handleHash [32]byte) (storage.LookedUpBackchannelAuthentication, error) {
	if *s.down {
		return storage.LookedUpBackchannelAuthentication{}, fmt.Errorf("db: %w", storage.ErrStoreUnavailable)
	}
	return s.BackchannelAuthenticationStore.LookupBackchannelAuthentication(ctx, handleHash)
}

// TestBackchannelInboxReportsAStoreOutage: a backchannel store that
// can't answer fails the listing and the bulk denial, rather than
// showing an empty inbox an account closure would take as done.
func TestBackchannelInboxReportsAStoreOutage(t *testing.T) {
	down := false
	h := newHarnessWithBackchannelOptions(t, outageBackchannelStore{memstore.NewBackchannelAuthenticationStore(), &down}, nil, func(d *server.Dependencies) {
		d.BackchannelSubjects = hintSubjects{known: map[string]bool{"user-1": true}}
		d.BackchannelInbox = memstore.NewBackchannelInbox()
	})
	beginFiled(t, h, "user-1")
	down = true
	if _, err := h.server.ListBackchannelInteractions(context.Background(), mustSubjectID(t, "user-1")); err == nil {
		t.Error("ListBackchannelInteractions with the store down = nil error, want the outage")
	}
	if n, err := h.server.DenyBackchannelInteractions(context.Background(), mustSubjectID(t, "user-1"), "closed"); err == nil || n != 0 {
		t.Errorf("DenyBackchannelInteractions with the store down = %d, %v, want 0 and the outage", n, err)
	}
}

// flakyRemoveInbox fails its first RemoveBackchannelRequest.
type flakyRemoveInbox struct {
	*memstore.BackchannelInbox
	failed *bool
}

func (b flakyRemoveInbox) RemoveBackchannelRequest(ctx context.Context, handleHash [32]byte) error {
	if !*b.failed {
		*b.failed = true
		return errors.New("inbox down")
	}
	return b.BackchannelInbox.RemoveBackchannelRequest(ctx, handleHash)
}

// TestDenyBackchannelInteractionsClearsStaleEntries: an entry left
// listed after its request was decided (its removal failed) is removed
// when a bulk denial finds the request already decided.
func TestDenyBackchannelInteractionsClearsStaleEntries(t *testing.T) {
	failed := false
	h := inboxHarness(t, flakyRemoveInbox{memstore.NewBackchannelInbox(), &failed})
	required := beginFiled(t, h, "user-1")
	approveAs(t, h, required.Handle, required.Interaction.Scope, "user-1")
	if len(inboxOf(t, h, "user-1")) != 1 {
		t.Fatal("the decided request isn't still listed, so the removal failure wasn't exercised")
	}
	if n, err := h.server.DenyBackchannelInteractions(context.Background(), mustSubjectID(t, "user-1"), "closed"); err != nil || n != 0 {
		t.Fatalf("DenyBackchannelInteractions = %d, %v, want 0, nil", n, err)
	}
	if left := inboxOf(t, h, "user-1"); len(left) != 0 {
		t.Errorf("inbox after the denial = %d requests, want the stale entry cleared", len(left))
	}
}

// TestBackchannelInboxSkipsAnEntryFiledUnderSomeoneElse: an entry whose
// request is bound to another user than the one it's filed under, as an
// entry a database writer moved would be, isn't listed for them.
func TestBackchannelInboxSkipsAnEntryFiledUnderSomeoneElse(t *testing.T) {
	inbox := &stubInbox{BackchannelInbox: memstore.NewBackchannelInbox()}
	h := inboxHarness(t, inbox)
	required := beginFiled(t, h, "user-1")
	handle := required.Handle.String()
	inbox.extra = []storage.BackchannelInboxEntry{inboxEntry(t, h, testIssuer, "user-2", handle, sha256.Sum256([]byte(handle)))}
	if pending := inboxOf(t, h, "user-2"); len(pending) != 0 {
		t.Errorf("inbox of user-2 = %d requests, want user-1's request left out", len(pending))
	}
}

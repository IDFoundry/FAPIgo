package sqlstore_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/sqlstore"
	"github.com/idfoundry/fapigo/storage"
)

// pushAt pushes reference for client-1 through s, expiring at expiresAt.
func pushAt(t *testing.T, s *sqlstore.TransactionStore, reference string, expiresAt time.Time) {
	t.Helper()
	must(t, s.CreatePAR(context.Background(), storage.NewPARRecord{
		Reference: reference, ClientID: "client-1", Request: []byte(`{"v":1}`), ExpiresAt: expiresAt,
	}))
}

// beginAt begins an interaction for reference through s under handle, at
// now.
func beginAt(t *testing.T, s *sqlstore.TransactionStore, reference, handle string, now time.Time) {
	t.Helper()
	_, err := s.BeginAuthorization(context.Background(), storage.BeginAuthorizationTransaction{
		Reference: reference, Handle: handle, HandleExpiresAt: now.Add(time.Minute), Now: now,
	})
	must(t, err)
}

// pushedRequestState is a state the authorization endpoint can find a
// request_uri's pushed request in: setup, if set, brings reference to it
// through s at now, and begins is whether an interaction can then be
// begun for it.
type pushedRequestState struct {
	name      string
	reference string
	setup     func(t *testing.T, s *sqlstore.TransactionStore, reference string, now time.Time)
	begins    bool
}

// pushedRequestStates are the states TestPushedRequestLookupAgreesWithBeginAuthorization
// checks, each with a reference of its own.
var pushedRequestStates = []pushedRequestState{
	{name: "never pushed", reference: "ref-unknown"},
	{name: "pushed", reference: "ref-pushed", begins: true, setup: func(t *testing.T, s *sqlstore.TransactionStore, reference string, now time.Time) {
		pushAt(t, s, reference, now.Add(time.Hour))
	}},
	{name: "begun, not completed", reference: "ref-begun", begins: true, setup: func(t *testing.T, s *sqlstore.TransactionStore, reference string, now time.Time) {
		pushAt(t, s, reference, now.Add(time.Hour))
		beginAt(t, s, reference, "handle-begun", now)
	}},
	{name: "completed", reference: "ref-completed", setup: func(t *testing.T, s *sqlstore.TransactionStore, reference string, now time.Time) {
		pushAt(t, s, reference, now.Add(time.Hour))
		beginAt(t, s, reference, "handle-completed", now)
		_, err := s.CompleteAuthorization(context.Background(), storage.CompleteAuthorizationTransaction{Handle: "handle-completed"})
		must(t, err)
	}},
	{name: "a nanosecond before its expiry", reference: "ref-expiring", begins: true, setup: func(t *testing.T, s *sqlstore.TransactionStore, reference string, now time.Time) {
		pushAt(t, s, reference, now.Add(time.Nanosecond))
	}},
	{name: "at its expiry", reference: "ref-expired-now", setup: func(t *testing.T, s *sqlstore.TransactionStore, reference string, now time.Time) {
		pushAt(t, s, reference, now)
	}},
	{name: "past its expiry", reference: "ref-expired", setup: func(t *testing.T, s *sqlstore.TransactionStore, reference string, now time.Time) {
		pushAt(t, s, reference, now.Add(-time.Second))
	}},
	{name: "a reference with a NUL", reference: "ref-\x00"},
	{name: "a reference that isn't UTF-8", reference: "ref-\xff"},
}

// In each state pushedRequestStates lists, plain or sealed, the lookup
// finds exactly what BeginAuthorization would begin: asked first, it
// finds what BeginAuthorization then begins, with the same client and
// expiry, and refuses, as an unknown request_uri rather than an outage,
// what BeginAuthorization refuses. A lookup refusing what
// BeginAuthorization begins would refuse a client its own request_uri;
// one finding what BeginAuthorization refuses would have the server
// claim an interaction slot for it.
func TestPushedRequestLookupAgreesWithBeginAuthorization(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		for name, opts := range map[string]sqlstore.Options{"Plain": {}, "Sealed": {Sealer: testSealer(t)}} {
			t.Run(name, func(t *testing.T) {
				d := newPlace(t, dialect).migratedWith(opts)
				now := time.Now()
				for _, state := range pushedRequestStates {
					checkLookupAgrees(t, d, state, now)
				}
			})
		}
	})
}

// checkLookupAgrees brings state's reference to its state in d at now,
// then asks the lookup and BeginAuthorization, in that order, at now:
// both must begin it, reading the same client and expiry, or both refuse
// it, the lookup with ErrNotFound and not as an outage, as state says.
func checkLookupAgrees(t *testing.T, d *sqlstore.DB, state pushedRequestState, now time.Time) {
	t.Helper()
	ctx := context.Background()
	if state.setup != nil {
		state.setup(t, d.Transactions(), state.reference, now)
	}
	found, lookupErr := d.PushedRequestLookup().LookupPushedRequest(ctx, storage.LookupPushedRequestTransaction{Reference: state.reference, Now: now})
	begun, beginErr := d.Transactions().BeginAuthorization(ctx, storage.BeginAuthorizationTransaction{
		Reference: state.reference, Handle: "handle-agreement " + state.name, HandleExpiresAt: now.Add(time.Minute), Now: now,
	})
	switch {
	case (lookupErr == nil) != state.begins:
		t.Errorf("%s: LookupPushedRequest = %v, want it to find the request: %t", state.name, lookupErr, state.begins)
	case (beginErr == nil) != state.begins:
		t.Errorf("%s: BeginAuthorization = %v, want it to begin the request: %t", state.name, beginErr, state.begins)
	case lookupErr != nil && (errors.Is(lookupErr, storage.ErrStoreUnavailable) || !errors.Is(lookupErr, sqlstore.ErrNotFound)):
		t.Errorf("%s: LookupPushedRequest = %v, want ErrNotFound, not an outage", state.name, lookupErr)
	case lookupErr == nil && (found.ClientID != begun.ClientID || !found.ExpiresAt.Equal(begun.ExpiresAt)):
		t.Errorf("%s: LookupPushedRequest = %+v, BeginAuthorization = client %q expiring %v: want the same", state.name, found, begun.ClientID, begun.ExpiresAt)
	}
}

// statementRecorder records the statements a hooked connection
// (hookedDB) begins.
type statementRecorder struct {
	mu         sync.Mutex
	statements []string
}

// hook is the statementHook hookedDB calls: it records each statement
// before it runs.
func (r *statementRecorder) hook(query string, after bool) {
	if after {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.statements = append(r.statements, query)
}

// take returns the statements recorded since it was last called.
func (r *statementRecorder) take() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	taken := r.statements
	r.statements = nil
	return taken
}

// The lookup is one SELECT, outside any transaction, whether it finds
// the request or not: it writes nothing, so made-up request_uris take
// no write from the database (on SQLite, from its one writer, which
// every replay-checked request waits for).
func TestPushedRequestLookupOnlyReads(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		p := newPlace(t, dialect)
		now := time.Now()
		pushAt(t, p.migrated().Transactions(), "ref-live", now.Add(time.Hour))
		var recorder statementRecorder
		lookup := p.handle(hookedDB(t, p, "", recorder.hook)).PushedRequestLookup()
		for reference, found := range map[string]bool{"ref-live": true, "ref-never-pushed": false} {
			_, err := lookup.LookupPushedRequest(context.Background(), storage.LookupPushedRequestTransaction{Reference: reference, Now: now})
			if (err == nil) != found {
				t.Errorf("LookupPushedRequest(%s) = %v, want it to find the request: %t", reference, err, found)
			}
			if statements := recorder.take(); len(statements) != 1 || !strings.HasPrefix(statements[0], "SELECT ") {
				t.Errorf("LookupPushedRequest(%s) ran %q, want one SELECT and nothing else", reference, statements)
			}
		}
	})
}

// pushesAcrossHandles is how many requests
// TestPushedRequestLookupSeesPushesMadeThroughAnotherHandle pushes at
// once.
const pushesAcrossHandles = 64

// The lookup sees, on every instance sharing a database, each CreatePAR
// that has returned, as storage.PushedRequestLookup requires: one that
// didn't would refuse a client the request_uri it was just given. Two
// handles on one database, each on a *sql.DB of its own as two server
// instances' are, look up what the other pushed, one push at a time and
// then while both push at once. TestPushedRequestLookupContract can't
// show it, with the one store and lookup its factory hands each subtest.
func TestPushedRequestLookupSeesPushesMadeThroughAnotherHandle(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		p := newPlace(t, dialect)
		p.migrated()
		first, _ := p.openPool()
		second, _ := p.openPool()
		handles := [2]*sqlstore.DB{first, second}
		for i := range 2 {
			must(t, pushSeenAcross(handles[i], handles[1-i], "ref-one-at-a-time-"+strconv.Itoa(i)))
		}
		checkConcurrentPushesSeenAcross(t, handles)
	})
}

// pushSeenAcross pushes reference through from and, once that has
// returned, looks it up through to: an error unless the lookup finds it,
// with the client and expiry pushed.
func pushSeenAcross(from, to *sqlstore.DB, reference string) error {
	ctx := context.Background()
	expires := time.Now().Add(time.Hour)
	if err := from.Transactions().CreatePAR(ctx, storage.NewPARRecord{
		Reference: reference, ClientID: "client-1", Request: []byte(`{"v":1}`), ExpiresAt: expires,
	}); err != nil {
		return fmt.Errorf("CreatePAR(%s): %w", reference, err)
	}
	found, err := to.PushedRequestLookup().LookupPushedRequest(ctx, storage.LookupPushedRequestTransaction{Reference: reference, Now: time.Now()})
	switch {
	case err != nil:
		return fmt.Errorf("a lookup of %s through the other handle, once its CreatePAR had returned: %w", reference, err)
	case found.ClientID != "client-1" || !found.ExpiresAt.Equal(expires):
		return fmt.Errorf("a lookup of %s through the other handle = %+v, want client-1 expiring %v", reference, found, expires)
	}
	return nil
}

// checkConcurrentPushesSeenAcross pushes pushesAcrossHandles requests at
// once, through both of handles in turn, each pusher then looking its
// request up through the other handle: every lookup finds its request.
func checkConcurrentPushesSeenAcross(t *testing.T, handles [2]*sqlstore.DB) {
	t.Helper()
	var missed atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range pushesAcrossHandles {
		wg.Go(func() {
			<-start
			if err := pushSeenAcross(handles[i%2], handles[1-i%2], "ref-concurrent-"+strconv.Itoa(i)); err != nil {
				missed.Add(1)
				t.Error(err)
			}
		})
	}
	close(start)
	wg.Wait()
	if n := missed.Load(); n != 0 {
		t.Fatalf("%d of %d lookups through the other handle missed a push that had returned", n, pushesAcrossHandles)
	}
}

// A lookup the database can't answer is an outage, whether or not the
// request was pushed: its error wraps storage.ErrStoreUnavailable, which
// the server answers with 500 server_error, and not ErrNotFound, which
// it would answer as a request_uri that is invalid, expired or already
// used. Here the database can't answer through a closed *sql.DB, nor,
// through an open one, on a context cancelled or past its deadline
// before the lookup, whose error then wraps the context's too: the
// lookup runs on the request's context, so a request that has given up
// doesn't run it, and the request's deadline bounds it when the
// database is slow.
func TestPushedRequestLookupOutage(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		p := newPlace(t, dialect)
		now := time.Now()
		d := p.migrated()
		pushAt(t, d.Transactions(), "ref-pushed", now.Add(time.Hour))
		closed, db := p.openPool()
		must(t, db.Close())
		cancelled, cancel := context.WithCancel(context.Background())
		cancel()
		pastDeadline, cancelPastDeadline := context.WithDeadline(context.Background(), now.Add(-time.Second))
		defer cancelPastDeadline()
		for _, reference := range []string{"ref-pushed", "ref-never-pushed"} {
			txn := storage.LookupPushedRequestTransaction{Reference: reference, Now: now}
			_, err := closed.PushedRequestLookup().LookupPushedRequest(context.Background(), txn)
			wantLookupOutage(t, err, reference+" through a closed *sql.DB")
			_, err = d.PushedRequestLookup().LookupPushedRequest(cancelled, txn)
			wantLookupOutage(t, err, reference+" on a cancelled context", context.Canceled)
			_, err = d.PushedRequestLookup().LookupPushedRequest(pastDeadline, txn)
			wantLookupOutage(t, err, reference+" on a context past its deadline", context.DeadlineExceeded)
		}
	})
}

// wantLookupOutage checks that err, the answer to a lookup (what
// describes it), is an outage: it wraps storage.ErrStoreUnavailable and
// each of causes, and not ErrNotFound.
func wantLookupOutage(t *testing.T, err error, what string, causes ...error) {
	t.Helper()
	if !errors.Is(err, storage.ErrStoreUnavailable) || errors.Is(err, sqlstore.ErrNotFound) {
		t.Errorf("LookupPushedRequest(%s) = %v, want an error wrapping storage.ErrStoreUnavailable, not ErrNotFound", what, err)
	}
	for _, cause := range causes {
		if !errors.Is(err, cause) {
			t.Errorf("LookupPushedRequest(%s) = %v, want it to wrap %v too", what, err, cause)
		}
	}
}

// authorizationEndpoint is a server's authorization endpoint, over the
// tables of p, which db reaches, so a test can count the rows a request
// to it leaves.
type authorizationEndpoint struct {
	t   *testing.T
	srv *server.Server
	p   *place
	db  *sql.DB
}

// get is the server's answer to a GET of its authorization endpoint
// naming clientID and requestURI, as anyone can send it: no cookie, and
// no client authentication, which the endpoint doesn't take.
func (e authorizationEndpoint) get(clientID fapi.ClientID, requestURI string) server.AuthorizationAction {
	e.t.Helper()
	query := url.Values{"client_id": {string(clientID)}, "request_uri": {requestURI}}
	req, err := server.BeginAuthorizationRequestFromHTTP(httptest.NewRequest(http.MethodGet, "https://as.example/authorize?"+query.Encode(), nil))
	must(e.t, err)
	action, err := e.srv.BeginAuthorization(context.Background(), req)
	must(e.t, err)
	return action
}

// rows is how many rows the replay and interactions tables hold.
func (e authorizationEndpoint) rows() [2]int {
	e.t.Helper()
	return [2]int{countRows(e.t, e.p, e.db, "replay"), countRows(e.t, e.p, e.db, "interactions")}
}

// wantRefused checks that a GET naming clientID and requestURI (what
// describes it) is answered with a local invalid_request_uri, and leaves
// no row in the replay or interactions table.
func (e authorizationEndpoint) wantRefused(clientID fapi.ClientID, requestURI, what string) {
	e.t.Helper()
	before := e.rows()
	action := e.get(clientID, requestURI)
	if refused, ok := action.(server.LocalErrorResponse); !ok || refused.Error.Code() != server.ErrorInvalidRequestURI {
		e.t.Fatalf("a GET of the authorization endpoint %s = %T, want a local invalid_request_uri", what, action)
	}
	if after := e.rows(); after != before {
		e.t.Fatalf("a GET of the authorization endpoint %s took the replay and interactions tables from %v rows to %v, want no change", what, before, after)
	}
}

// madeUpRequests is how many GETs naming a made-up request_uri
// TestAuthorizationWithPushedRequestLookupWritesNothingUnusable sends.
const madeUpRequests = 20

// With the pushed request lookup, the authorization endpoint writes
// nothing for a request_uri no interaction can be begun for, on either
// database. Nobody authenticates there, and before, each GET naming a
// made-up request_uri, from anyone, with any client_id, left an
// interaction slot in the replay table for as long as a pushed request
// lives, a durable commit on SQLite's one writer. Now it's refused with
// invalid_request_uri after one read, and so is a pushed request_uri
// presented with another client_id, again once its interaction has
// completed, or once it has expired: none leaves a replay row or an
// interaction. A pushed request_uri presented with its own client still
// begins, claiming its one slot, so the tables counted are the ones the
// server writes.
func TestAuthorizationWithPushedRequestLookupWritesNothingUnusable(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		ctx := context.Background()
		p := newPlace(t, dialect)
		d := p.migrated()
		_, db := p.open()
		app := newFlowClient(t, d)
		clock := &movingClock{now: time.Now()}
		cfg, deps := flowDeployment(t, d, d.Grants(), clock)
		deps.PushedRequestLookup = d.PushedRequestLookup()
		srv, err := server.New(cfg, deps)
		must(t, err)
		e := authorizationEndpoint{t: t, srv: srv, p: p, db: db}

		for i := range madeUpRequests {
			n := strconv.Itoa(i)
			e.wantRefused(fapi.ClientID("anyone-"+n), "urn:ietf:params:oauth:request_uri:made-up-"+n, "naming a made-up request_uri")
		}
		if rows := e.rows(); rows != [2]int{} {
			t.Fatalf("after %d GETs naming made-up request_uris: %d replay rows and %d interactions, want none", madeUpRequests, rows[0], rows[1])
		}

		requestURI := app.push(ctx, srv)
		e.wantRefused("another-client", requestURI, "naming a pushed request_uri with another client_id")
		action := e.get(flowClientID, requestURI)
		if rows := e.rows(); rows != [2]int{1, 1} {
			t.Fatalf("beginning the pushed request_uri: %d replay rows and %d interactions, want 1 and 1", rows[0], rows[1])
		}
		app.approve(ctx, srv, clock.Now(), action, "grant-1")
		e.wantRefused(flowClientID, requestURI, "naming a request_uri whose interaction has completed")

		expiring := app.push(ctx, srv)
		clock.advance(cfg.Limits.PushedRequestLifetime + time.Second)
		e.wantRefused(flowClientID, expiring, "naming a request_uri that has expired")
	})
}

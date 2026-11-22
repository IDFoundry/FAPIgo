package server_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// cancellingBackchannelStore counts lookups, and calls cancel, when set,
// at each: a caller giving up while its listing reads the store.
type cancellingBackchannelStore struct {
	storage.BackchannelAuthenticationStore
	cancel  context.CancelFunc
	lookups int
}

func (s *cancellingBackchannelStore) LookupBackchannelAuthentication(ctx context.Context, handleHash [32]byte) (storage.LookedUpBackchannelAuthentication, error) {
	s.lookups++
	if s.cancel != nil {
		s.cancel()
	}
	return s.BackchannelAuthenticationStore.LookupBackchannelAuthentication(ctx, handleHash)
}

// TestBackchannelInboxListingStopsWhenTheContextEnds: a listing reads no
// more of the inbox once its context ends, and fails with the context's
// error rather than returning part of it; a bulk denial then denies
// nothing.
func TestBackchannelInboxListingStopsWhenTheContextEnds(t *testing.T) {
	store := &cancellingBackchannelStore{BackchannelAuthenticationStore: memstore.NewBackchannelAuthenticationStore()}
	h := newHarnessWithBackchannelOptions(t, store, nil, func(d *server.Dependencies) {
		d.BackchannelSubjects = hintSubjects{known: map[string]bool{"user-1": true}}
		d.BackchannelInbox = memstore.NewBackchannelInbox()
	})
	for range 3 {
		beginFiled(t, h, "user-1")
	}
	c := inboxCancellation{h: h, store: store, subject: mustSubjectID(t, "user-1")}

	t.Run("list", c.testList)
	t.Run("deny", c.testDeny)
	t.Run("deadline already passed", c.testDeadlinePassed)
}

// inboxCancellation is TestBackchannelInboxListingStopsWhenTheContextEnds'
// server, with three requests pending for subject, and the store that
// counts its reads of them.
type inboxCancellation struct {
	h       harness
	store   *cancellingBackchannelStore
	subject server.SubjectID
}

// cancelledAtFirstLookup is a context c's store cancels as it reads the
// first request.
func (c inboxCancellation) cancelledAtFirstLookup(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	c.store.cancel, c.store.lookups = cancel, 0
	t.Cleanup(func() { c.store.cancel = nil })
	return ctx
}

// testList: a listing stops after the read that ended its context.
func (c inboxCancellation) testList(t *testing.T) {
	pending, err := c.h.server.ListBackchannelInteractions(c.cancelledAtFirstLookup(t), c.subject)
	if !errors.Is(err, context.Canceled) || pending != nil {
		t.Fatalf("ListBackchannelInteractions = %d requests, %v; want none and context.Canceled", len(pending), err)
	}
	if c.store.lookups != 1 {
		t.Errorf("the listing read %d requests, want it to stop after the first", c.store.lookups)
	}
}

// testDeny: a bulk denial whose listing stops denies nothing.
func (c inboxCancellation) testDeny(t *testing.T) {
	n, err := c.h.server.DenyBackchannelInteractions(c.cancelledAtFirstLookup(t), c.subject, "closed")
	if !errors.Is(err, context.Canceled) || n != 0 {
		t.Fatalf("DenyBackchannelInteractions = %d, %v; want 0 and context.Canceled", n, err)
	}
	if c.store.lookups != 1 {
		t.Errorf("the denial's listing read %d requests, want it to stop after the first", c.store.lookups)
	}
	if left := inboxOf(t, c.h, "user-1"); len(left) != 3 {
		t.Errorf("inbox after the cancelled denial = %d requests, want all 3 still pending", len(left))
	}
}

// testDeadlinePassed: a listing whose deadline has already passed reads
// nothing.
func (c inboxCancellation) testDeadlinePassed(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Unix(0, 0))
	defer cancel()
	c.store.lookups = 0
	if _, err := c.h.server.ListBackchannelInteractions(ctx, c.subject); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ListBackchannelInteractions past its deadline = %v, want context.DeadlineExceeded", err)
	}
	if c.store.lookups != 0 {
		t.Errorf("the listing read %d requests past its deadline, want none", c.store.lookups)
	}
}

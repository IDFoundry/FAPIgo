package server_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// refusingLookupStore refuses every lookup of the requests whose handle
// hashes are in refused with lookupErr; with foreign set, it instead
// returns their request records rewritten as another issuer's.
type refusingLookupStore struct {
	storage.BackchannelAuthenticationStore
	refused   map[[32]byte]bool
	lookupErr error
	foreign   bool
}

func (s *refusingLookupStore) LookupBackchannelAuthentication(ctx context.Context, handleHash [32]byte) (storage.LookedUpBackchannelAuthentication, error) {
	found, err := s.BackchannelAuthenticationStore.LookupBackchannelAuthentication(ctx, handleHash)
	if err != nil || !s.refused[handleHash] {
		return found, err
	}
	if !s.foreign {
		return storage.LookedUpBackchannelAuthentication{}, s.lookupErr
	}
	var record map[string]any
	if err := json.Unmarshal(found.Request, &record); err != nil {
		return storage.LookedUpBackchannelAuthentication{}, err
	}
	record["iss"] = "https://other-as.example"
	found.Request, err = json.Marshal(record)
	return found, err
}

// refusingLookupHarness is an inbox harness holding two requests filed
// for user-1, whose backchannel store refuses lookups of the second
// (returned as refused) as store says, once refuse(true) is called, and
// answers them again after refuse(false).
func refusingLookupHarness(t *testing.T, store *refusingLookupStore) (h harness, kept, refused server.BackchannelInteractionRequired, refuse func(bool)) {
	t.Helper()
	store.BackchannelAuthenticationStore = memstore.NewBackchannelAuthenticationStore()
	store.refused = map[[32]byte]bool{}
	h = newHarnessWithBackchannelOptions(t, store, nil, func(d *server.Dependencies) {
		d.BackchannelSubjects = hintSubjects{known: map[string]bool{"user-1": true}}
		d.BackchannelInbox = memstore.NewBackchannelInbox()
	})
	kept = beginFiled(t, h, "user-1")
	refused = beginFiled(t, h, "user-1")
	return h, kept, refused, func(on bool) { store.refused[sha256.Sum256([]byte(refused.Handle.String()))] = on }
}

// listOnly checks ListBackchannelInteractions for user-1 at h lists only
// want, with an error exactly when wantErr is set.
func listOnly(t *testing.T, h harness, want server.BackchannelInteractionRequired, wantErr bool) {
	t.Helper()
	pending, err := h.server.ListBackchannelInteractions(context.Background(), mustSubjectID(t, "user-1"))
	if (err != nil) != wantErr {
		t.Fatalf("ListBackchannelInteractions error = %v, want an error: %v", err, wantErr)
	}
	if len(pending) != 1 || pending[0].Handle.String() != want.Handle.String() {
		t.Fatalf("ListBackchannelInteractions = %d requests, want only the one whose lookup succeeds", len(pending))
	}
}

// TestListBackchannelInteractionsSkipsAGoneRequest: an entry whose
// request the store says is gone (storage.ErrBackchannelAuthenticationNotFound)
// is left out without an error.
func TestListBackchannelInteractionsSkipsAGoneRequest(t *testing.T) {
	h, kept, _, refuse := refusingLookupHarness(t, &refusingLookupStore{lookupErr: fmt.Errorf("db: %w", storage.ErrBackchannelAuthenticationNotFound)})
	refuse(true)
	listOnly(t, h, kept, false)
}

// TestListBackchannelInteractionsReportsARefusedLookup: an entry whose
// lookup the store refuses with an error that doesn't say the request is
// gone, or whose request record isn't this server's own, is reported,
// with the other requests still listed, rather than silently left out.
func TestListBackchannelInteractionsReportsARefusedLookup(t *testing.T) {
	t.Run("plain error", func(t *testing.T) {
		h, kept, _, refuse := refusingLookupHarness(t, &refusingLookupStore{lookupErr: errors.New("db: refused")})
		refuse(true)
		listOnly(t, h, kept, true)
	})
	t.Run("another issuer's request record", func(t *testing.T) {
		h, kept, _, refuse := refusingLookupHarness(t, &refusingLookupStore{foreign: true})
		refuse(true)
		listOnly(t, h, kept, true)
	})
}

// TestDenyBackchannelInteractionsReportsARefusedLookup: an entry the
// listing couldn't read doesn't stop the other requests being denied; it
// isn't counted, is reported, and stays in the inbox.
func TestDenyBackchannelInteractionsReportsARefusedLookup(t *testing.T) {
	h, _, refused, refuse := refusingLookupHarness(t, &refusingLookupStore{lookupErr: errors.New("db: refused")})
	refuse(true)
	n, err := h.server.DenyBackchannelInteractions(context.Background(), mustSubjectID(t, "user-1"), "closed")
	if err == nil || n != 1 {
		t.Fatalf("DenyBackchannelInteractions = %d, %v, want 1 and an error for the unreadable entry", n, err)
	}
	refuse(false)
	if left := inboxOf(t, h, "user-1"); len(left) != 1 || left[0].Handle.String() != refused.Handle.String() {
		t.Errorf("inbox after the denial = %d requests, want only the unreadable one, still pending", len(left))
	}
}

// TestDenyBackchannelInteractionsClearsAGoneRequest: a request the store
// says is gone (storage.ErrBackchannelAuthenticationNotFound) when it's
// denied is passed over, not counted, and its entry removed.
func TestDenyBackchannelInteractionsClearsAGoneRequest(t *testing.T) {
	h := refusingDecideHarness(t, fmt.Errorf("db: %w", storage.ErrBackchannelAuthenticationNotFound))
	if n, err := h.server.DenyBackchannelInteractions(context.Background(), mustSubjectID(t, "user-1"), "closed"); err != nil || n != 0 {
		t.Fatalf("DenyBackchannelInteractions(request gone) = %d, %v, want 0, nil", n, err)
	}
	if left := inboxOf(t, h, "user-1"); len(left) != 0 {
		t.Errorf("inbox after the denial = %d requests, want the stale entry cleared", len(left))
	}
}

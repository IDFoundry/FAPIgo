package server_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// TestLookupBackchannelInteractionOnAnotherInstance covers the reason to
// look an interaction up: a request begun on one instance, shown on
// another that shares the backchannel store.
func TestLookupBackchannelInteractionOnAnotherInstance(t *testing.T) {
	store := memstore.NewBackchannelAuthenticationStore()
	began := newHarnessWithBackchannelStore(t, store)
	other := newHarnessWithBackchannelStore(t, store)

	params := standardBackchannelParams(t)
	params["binding_message"] = jsonRaw(t, "W4SCT")
	required := beginBackchannel(t, began, params)

	got, err := other.server.LookupBackchannelInteraction(context.Background(), required.Handle)
	if err != nil {
		t.Fatalf("LookupBackchannelInteraction: %v", err)
	}
	if !reflect.DeepEqual(got, required.Interaction) {
		t.Errorf("looked up %+v, want what BeginBackchannelAuthentication returned, %+v", got, required.Interaction)
	}
}

func TestLookupBackchannelInteractionUnknownHandle(t *testing.T) {
	h, _ := newHarnessWithBackchannel(t)
	handle, err := server.ParseBackchannelAuthenticationHandle("unknown-handle-value-that-is-long-enough-000000")
	if err != nil {
		t.Skipf("handle format: %v", err)
	}
	_, err = h.server.LookupBackchannelInteraction(context.Background(), handle)
	var serverErr *server.Error
	if !errors.As(err, &serverErr) || serverErr.Code() != server.ErrorInvalidRequest {
		t.Errorf("LookupBackchannelInteraction(unknown) = %v, want invalid_request", err)
	}
}

func TestLookupBackchannelInteractionWithoutCIBA(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	if _, err := h.server.LookupBackchannelInteraction(context.Background(), server.BackchannelAuthenticationHandle{}); err == nil {
		t.Error("LookupBackchannelInteraction without CIBA configured = nil error, want error")
	}
}

// corruptLookupStore returns a stored request that doesn't decode.
type corruptLookupStore struct {
	*memstore.BackchannelAuthenticationStore
}

func (s corruptLookupStore) LookupBackchannelAuthentication(ctx context.Context, handleHash [32]byte) (storage.LookedUpBackchannelAuthentication, error) {
	rec, err := s.BackchannelAuthenticationStore.LookupBackchannelAuthentication(ctx, handleHash)
	rec.Request = json.RawMessage(`"not a request record"`)
	return rec, err
}

func TestLookupBackchannelInteractionServerErrors(t *testing.T) {
	store := memstore.NewBackchannelAuthenticationStore()
	required := beginBackchannel(t, newHarnessWithBackchannelStore(t, store), standardBackchannelParams(t))

	for name, h := range map[string]harness{
		"client no longer resolvable": newHarnessWithBackchannelOptions(t, store, nil, func(d *server.Dependencies) {
			d.Clients = &fakeClientRepository{clients: map[fapi.ClientID]storage.RegisteredClient{}}
		}),
		"stored request unreadable": newHarnessWithBackchannelStore(t, corruptLookupStore{store}),
	} {
		_, err := h.server.LookupBackchannelInteraction(context.Background(), required.Handle)
		var serverErr *server.Error
		if !errors.As(err, &serverErr) || serverErr.Code() != server.ErrorServerError {
			t.Errorf("%s: LookupBackchannelInteraction = %v, want server_error", name, err)
		}
	}
}

package payment

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// failingReplayStore can't record anything.
type failingReplayStore struct{}

func (failingReplayStore) UseOnce(context.Context, storage.ReplayUse) error {
	return errors.New("replay store unavailable")
}

// TestApprovalUsedOnceAcrossInstances covers two instances of the API
// sharing the bank's replay store: whichever sees an approval second
// refuses it, and a store that can't be reached refuses too.
func TestApprovalUsedOnceAcrossInstances(t *testing.T) {
	shared := memstore.NewReplayStore()
	first, second := &api{replay: shared}, &api{replay: shared}
	authz := resource.AuthorizationContext{Key: "token-1", ExpiresAt: time.Now().Add(time.Minute)}
	if !first.useOnce(context.Background(), authz) {
		t.Fatal("first use refused")
	}
	if second.useOnce(context.Background(), authz) {
		t.Error("the same approval was used again on another instance")
	}
	if !second.useOnce(context.Background(), resource.AuthorizationContext{Key: "token-2", ExpiresAt: authz.ExpiresAt}) {
		t.Error("another approval was refused")
	}
	if (&api{replay: failingReplayStore{}}).useOnce(context.Background(), authz) {
		t.Error("an unreachable replay store allowed the approval")
	}
}

package checkout

import (
	"context"
	"encoding/json"
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

// approvalToken is an access token from the grant codeGrantID names.
func approvalToken(key, codeGrantID string) resource.AuthorizationContext {
	return resource.AuthorizationContext{
		Key: key, ExpiresAt: time.Now().Add(time.Minute),
		Claims: map[string]json.RawMessage{"code_grant_id": json.RawMessage(`"` + codeGrantID + `"`)},
	}
}

// TestApprovalUsedOnceAcrossInstances covers two instances of the API
// sharing the bank's replay store: whichever sees an approval second
// refuses it, and a store that can't be reached refuses too.
func TestApprovalUsedOnceAcrossInstances(t *testing.T) {
	shared := memstore.NewReplayStore()
	first, second := &api{replay: shared, grantLifetime: time.Hour}, &api{replay: shared, grantLifetime: time.Hour}
	authz := approvalToken("token-1", "grant-1")
	if !first.useOnce(context.Background(), authz) {
		t.Fatal("first use refused")
	}
	if second.useOnce(context.Background(), authz) {
		t.Error("the same approval was used again on another instance")
	}
	if !second.useOnce(context.Background(), approvalToken("token-2", "grant-2")) {
		t.Error("another approval was refused")
	}
	if (&api{replay: failingReplayStore{}}).useOnce(context.Background(), approvalToken("token-3", "grant-3")) {
		t.Error("an unreachable replay store allowed the approval")
	}
}

// TestApprovalUsedOnceAcrossRefresh: a refreshed access token has a new
// Key but carries the same approval, so it can't be used again; and a
// token naming no grant is refused outright.
func TestApprovalUsedOnceAcrossRefresh(t *testing.T) {
	a := &api{replay: memstore.NewReplayStore(), grantLifetime: time.Hour}
	if !a.useOnce(context.Background(), approvalToken("token-1", "grant-1")) {
		t.Fatal("first use refused")
	}
	if a.useOnce(context.Background(), approvalToken("token-1-refreshed", "grant-1")) {
		t.Error("a refreshed token used the same approval again")
	}
	if a.useOnce(context.Background(), resource.AuthorizationContext{Key: "token-4", ExpiresAt: time.Now().Add(time.Minute)}) {
		t.Error("a token naming no grant was allowed")
	}
}

package server

import (
	"context"
	"errors"
	"testing"
	"time"
)

// failingRevocationStore fails every Revoke and IsRevoked.
type failingRevocationStore struct{}

func (failingRevocationStore) Revoke(context.Context, string, time.Time) error {
	return errors.New("store down")
}

func (failingRevocationStore) IsRevoked(context.Context, string) (bool, error) {
	return false, errors.New("store down")
}

type fixedTestClock struct{}

func (fixedTestClock) Now() time.Time { return time.Unix(1_700_000_000, 0) }

// TestGrantRevocationFailsClosed covers the paths where a grant's
// revocation can't be recorded or checked: each is an error, never a
// silently unrevoked grant.
func TestGrantRevocationFailsClosed(t *testing.T) {
	ctx := context.Background()
	grant := grantRecord{GrantID: "grant-1"}

	failing := &Server{deps: Dependencies{Revocation: failingRevocationStore{}, Clock: fixedTestClock{}}}
	if err := failing.RevokeGrant(ctx, "grant-1"); err == nil {
		t.Error("RevokeGrant with a failing store = nil error, want error")
	}
	if err := failing.checkGrantNotRevoked(ctx, grant); err == nil || err.Code() != ErrorServerError {
		t.Errorf("checkGrantNotRevoked with a failing store = %v, want server_error", err)
	}

	// A grant ID issued earlier, after which the deployment switched to
	// a store it can't check.
	for name, sink := range map[string]RevocationSink{"NoRevocation": NoRevocation{}, "*NoRevocation": &NoRevocation{}} {
		unchecked := &Server{deps: Dependencies{Revocation: sink}}
		if err := unchecked.checkGrantNotRevoked(ctx, grant); err == nil || err.Code() != ErrorServerError {
			t.Errorf("checkGrantNotRevoked with %s = %v, want server_error", name, err)
		}
		if _, ok := unchecked.grantRevocationReader(); ok {
			t.Errorf("grantRevocationReader(%s) reports a reader", name)
		}
	}

	// No grant ID: nothing to check, whatever the store.
	if err := failing.checkGrantNotRevoked(ctx, grantRecord{}); err != nil {
		t.Errorf("checkGrantNotRevoked(no grant ID) = %v, want nil", err)
	}
}

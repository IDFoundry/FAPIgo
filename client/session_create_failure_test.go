package client_test

import (
	"context"
	"errors"
	"testing"

	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/storage"
)

// failingCreateSessionStore can't persist a session.
type failingCreateSessionStore struct{ fakeSessionStore }

func (*failingCreateSessionStore) Create(context.Context, storage.NewSession) error {
	return errors.New("session store unavailable")
}

// TestBeginAuthorizationFailsWhenTheSessionCantBePersisted covers a
// session store that refuses the session: BeginAuthorization fails
// rather than sending the browser to an authorization it couldn't
// complete.
func TestBeginAuthorizationFailsWhenTheSessionCantBePersisted(t *testing.T) {
	c, _, _ := newTestClientWith(t, false, func(_ *client.Config, d *client.Dependencies) {
		d.Sessions = &failingCreateSessionStore{}
	})
	_, err := c.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{Scope: []string{"openid", "accounts"}})
	var cerr *client.Error
	if !errors.As(err, &cerr) || cerr.Code() != client.ErrorInternal {
		t.Fatalf("BeginAuthorization(failing session store) = %v, want internal", err)
	}
}

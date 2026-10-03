package client_test

import (
	"context"
	"testing"

	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// appSessionStore is a native app's own session store: nothing but
// this app writes it, which it declares.
type appSessionStore struct{ storage.SessionStore }

func (appSessionStore) Capabilities() storage.Capabilities {
	return storage.Capabilities{SingleUserAgent: true}
}

// TestCallbackWithoutSessionForASingleUserAgentStore covers an app the
// operating system stopped mid-authorization: relaunched, it holds no
// SessionHandle, and completes from the callback alone, its store
// declaring it holds only this app's sessions. Under Message Signing the
// state comes from the verified signed response.
func TestCallbackWithoutSessionForASingleUserAgentStore(t *testing.T) {
	for name, messageSigned := range map[string]bool{"plain": false, "JARM": true} {
		t.Run(name, func(t *testing.T) {
			c, as, _ := newTestClientWith(t, messageSigned, func(_ *client.Config, d *client.Dependencies) {
				d.Sessions = appSessionStore{memstore.NewSessionStore()}
			})
			ctx := context.Background()
			session, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid", "accounts"}})
			if err != nil {
				t.Fatalf("BeginAuthorization: %v", err)
			}
			rawQuery := as.callbackFor(t, session.Handle().String(), "auth-code-123", "")
			result, err := c.CompleteAuthorization(ctx, client.AuthorizationCallback{RawQuery: rawQuery})
			if err != nil {
				t.Fatalf("CompleteAuthorization(no Session): %v", err)
			}
			if _, ok := result.(client.CompletionSuccess); !ok {
				t.Fatalf("result = %T, want client.CompletionSuccess", result)
			}
		})
	}
}

// TestCallbackWithoutSessionStillRefused covers what the declaration
// doesn't change: a store that doesn't declare it still needs the
// handle, a callback whose state no session in the store has is still
// refused, and a handle given is still compared.
func TestCallbackWithoutSessionStillRefused(t *testing.T) {
	ctx := context.Background()
	t.Run("store not declaring it", func(t *testing.T) {
		c, as, _ := newTestClient(t, false)
		session, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid"}})
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.CompleteAuthorization(ctx, client.AuthorizationCallback{RawQuery: as.callbackFor(t, session.Handle().String(), "c", "")})
		if code := clientErrorCode(t, err); code != client.ErrorInvalidRequest {
			t.Errorf("error code = %q, want %q", code, client.ErrorInvalidRequest)
		}
	})
	declaring := func(t *testing.T) (*client.Client, *fakeAS) {
		c, as, _ := newTestClientWith(t, false, func(_ *client.Config, d *client.Dependencies) {
			d.Sessions = appSessionStore{memstore.NewSessionStore()}
		})
		return c, as
	}
	t.Run("a state this app never began", func(t *testing.T) {
		c, as := declaring(t)
		// An attacker's callback, from a flow begun elsewhere: its state
		// is in no session this app's store holds.
		_, err := c.CompleteAuthorization(ctx, client.AuthorizationCallback{RawQuery: as.callbackFor(t, "attackers-own-state-0123456789abcdef", "c", "")})
		if code := clientErrorCode(t, err); code != client.ErrorInvalidRequest {
			t.Errorf("error code = %q, want %q", code, client.ErrorInvalidRequest)
		}
	})
	t.Run("a handle that doesn't match", func(t *testing.T) {
		c, as := declaring(t)
		first, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid"}})
		if err != nil {
			t.Fatal(err)
		}
		second, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid"}})
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.CompleteAuthorization(ctx, client.AuthorizationCallback{RawQuery: as.callbackFor(t, first.Handle().String(), "c", ""), Session: second.Handle()})
		if code := clientErrorCode(t, err); code != client.ErrorInvalidRequest {
			t.Errorf("error code = %q, want %q", code, client.ErrorInvalidRequest)
		}
	})
}

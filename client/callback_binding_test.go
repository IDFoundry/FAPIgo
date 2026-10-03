package client_test

import (
	"context"
	"strings"
	"testing"

	"github.com/idfoundry/fapigo/client"
)

// TestCallbackWithoutSessionForADeviceLocalStore covers an app the
// operating system stopped mid-authorization: relaunched, it holds no
// SessionHandle, and completes from the callback alone, configured with
// CallbackBindingDeviceLocalStore. Under Message Signing the state comes
// from the verified signed response.
func TestCallbackWithoutSessionForADeviceLocalStore(t *testing.T) {
	for name, messageSigned := range map[string]bool{"plain": false, "JARM": true} {
		t.Run(name, func(t *testing.T) {
			c, as, _ := newTestClientWith(t, messageSigned, func(cfg *client.Config, _ *client.Dependencies) {
				cfg.CallbackBinding = client.CallbackBindingDeviceLocalStore
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

// TestCallbackWithoutSessionStillRefused covers what the binding
// doesn't change: the default still needs the handle, a callback whose
// state no session in the store has is still refused, and a handle
// given is still compared.
func TestCallbackWithoutSessionStillRefused(t *testing.T) {
	ctx := context.Background()
	t.Run("the default binding", func(t *testing.T) {
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
		c, as, _ := newTestClientWith(t, false, func(cfg *client.Config, _ *client.Dependencies) {
			cfg.CallbackBinding = client.CallbackBindingDeviceLocalStore
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

func TestNewRefusesAnUnknownCallbackBinding(t *testing.T) {
	cfg, deps := validConfig(t), validDependencies(t)
	cfg.CallbackBinding = 9
	if _, err := client.New(cfg, deps); err == nil {
		t.Error("New accepted an unknown CallbackBinding")
	}
}

// TestMissingSessionErrorPointsAtTheHandle covers the refusal a web
// client that forgot its cookie meets: it says to pass the handle, and
// doesn't advertise turning the binding off.
func TestMissingSessionErrorPointsAtTheHandle(t *testing.T) {
	c, as, _ := newTestClient(t, false)
	session, err := c.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{Scope: []string{"openid"}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.CompleteAuthorization(context.Background(), client.AuthorizationCallback{RawQuery: as.callbackFor(t, session.Handle().String(), "c", "")})
	if err == nil || !strings.Contains(err.Error(), "sessioncookie") || strings.Contains(err.Error(), "DeviceLocal") {
		t.Errorf("error = %v, want it to point at the handle and sessioncookie, not the device-local binding", err)
	}
}

package server_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// hintChecker is a BackchannelHintChecker answering err for every hint
// except known, and recording what it was asked.
type hintChecker struct {
	known  string
	err    error
	calls  int
	client fapi.ClientID
	hints  server.BackchannelAuthenticationHints
}

func (c *hintChecker) CheckBackchannelHints(_ context.Context, clientID fapi.ClientID, hints server.BackchannelAuthenticationHints) error {
	c.calls++
	c.client, c.hints = clientID, hints
	if string(hints.LoginHint) == c.known {
		return nil
	}
	return c.err
}

// countingBackchannelStore counts the requests stored.
type countingBackchannelStore struct {
	storage.BackchannelAuthenticationStore
	created int
}

func (s *countingBackchannelStore) CreateBackchannelAuthentication(ctx context.Context, record storage.NewBackchannelAuthentication) error {
	s.created++
	return s.BackchannelAuthenticationStore.CreateBackchannelAuthentication(ctx, record)
}

func beginWithHint(t *testing.T, checker server.BackchannelHintChecker, loginHint string) (server.BackchannelAuthenticationAction, *countingBackchannelStore) {
	t.Helper()
	store := &countingBackchannelStore{BackchannelAuthenticationStore: memstore.NewBackchannelAuthenticationStore()}
	h := newHarnessWithBackchannelOptions(t, store, nil, func(d *server.Dependencies) { d.BackchannelHints = checker })
	params := standardBackchannelParams(t)
	params["login_hint"] = jsonRaw(t, loginHint)
	action, err := h.server.BeginBackchannelAuthentication(context.Background(), server.BeginBackchannelAuthenticationRequest{
		HTTP: server.FormRequest{Parameters: backchannelFormParams(h.clientAssertion(t), h.backchannelRequestObject(t, params))},
	})
	if err != nil {
		t.Fatalf("BeginBackchannelAuthentication: %v", err)
	}
	return action, store
}

// TestBackchannelHintsRefuseBeforeStoring covers CIBA §13's
// unknown_user_id and expired_login_hint_token: a request the checker
// refuses gets that error, and is never stored.
func TestBackchannelHintsRefuseBeforeStoring(t *testing.T) {
	for _, tc := range []struct {
		err    error
		code   server.ErrorCode
		status int
	}{
		{fmt.Errorf("no customer %q: %w", "nobody", server.ErrUnknownUserID), server.ErrorUnknownUserID, 400},
		{server.ErrExpiredLoginHintToken, server.ErrorExpiredLoginHintToken, 400},
		{errors.New("customer directory unavailable"), server.ErrorServerError, 500},
	} {
		t.Run(string(tc.code), func(t *testing.T) {
			checker := &hintChecker{known: "user-1", err: tc.err}
			action, store := beginWithHint(t, checker, "nobody")
			localErr, ok := action.(server.BackchannelAuthenticationLocalError)
			if !ok {
				t.Fatalf("action = %T, want BackchannelAuthenticationLocalError", action)
			}
			if localErr.Error.Code() != tc.code || localErr.Error.HTTPStatus() != tc.status {
				t.Errorf("error = %s %d, want %s %d", localErr.Error.Code(), localErr.Error.HTTPStatus(), tc.code, tc.status)
			}
			if store.created != 0 {
				t.Errorf("%d requests stored, want none", store.created)
			}
			if checker.client != testClientID || checker.hints.LoginHint != "nobody" {
				t.Errorf("checker saw client %q, hints %+v", checker.client, checker.hints)
			}
		})
	}
}

func TestBackchannelHintsAcceptKnownUser(t *testing.T) {
	checker := &hintChecker{known: "user-1", err: server.ErrUnknownUserID}
	action, store := beginWithHint(t, checker, "user-1")
	required, ok := action.(server.BackchannelInteractionRequired)
	if !ok {
		t.Fatalf("action = %T, want BackchannelInteractionRequired", action)
	}
	if required.Interaction.Hints.LoginHint != "user-1" || store.created != 1 || checker.calls != 1 {
		t.Errorf("hints %+v, %d stored, %d checks; want user-1, 1, 1", required.Interaction.Hints, store.created, checker.calls)
	}
}

// TestBackchannelHintsNotAskedForUnauthenticatedClient covers the check
// running only after client authentication: an unauthenticated caller
// can't learn whether a hint names a user.
func TestBackchannelHintsNotAskedForUnauthenticatedClient(t *testing.T) {
	checker := &hintChecker{err: server.ErrUnknownUserID}
	store := memstore.NewBackchannelAuthenticationStore()
	h := newHarnessWithBackchannelOptions(t, store, nil, func(d *server.Dependencies) { d.BackchannelHints = checker })
	params := standardBackchannelParams(t)
	action, err := h.server.BeginBackchannelAuthentication(context.Background(), server.BeginBackchannelAuthenticationRequest{
		HTTP: server.FormRequest{Parameters: backchannelFormParams("not-a-client-assertion", h.backchannelRequestObject(t, params))},
	})
	if err != nil {
		t.Fatalf("BeginBackchannelAuthentication: %v", err)
	}
	if localErr, ok := action.(server.BackchannelAuthenticationLocalError); !ok || localErr.Error.Code() != server.ErrorInvalidClient {
		t.Fatalf("action = %+v, want invalid_client", action)
	}
	if checker.calls != 0 {
		t.Error("the hint was checked for an unauthenticated client")
	}
}

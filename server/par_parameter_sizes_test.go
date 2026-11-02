package server_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// plainFormParametersWith is plainFormParameters with overrides
// replacing (or, for a name it doesn't send, adding) parameters.
func plainFormParametersWith(t *testing.T, assertion string, overrides map[string]string) []server.FormParameter {
	t.Helper()
	params := plainFormParameters(t, assertion, nil)
	for i, p := range params {
		if v, ok := overrides[p.Name]; ok {
			params[i].Value = v
		}
	}
	for name, v := range overrides {
		if !slices.ContainsFunc(params, func(p server.FormParameter) bool { return p.Name == name }) {
			params = append(params, formParam(name, v))
		}
	}
	return params
}

// TestPushAuthorizationRequestBoundsCoreParameterSizes: each core
// parameter a pushed request stores has a size bound of its own, below
// the 1 MiB form limit, so one pushed request can't carry (and have
// every later step decode) hundreds of kilobytes. One over its bound is
// refused with invalid_request, before anything is stored.
func TestPushAuthorizationRequestBoundsCoreParameterSizes(t *testing.T) {
	for name, value := range map[string]string{
		"state":          strings.Repeat("s", 4<<10+1),
		"nonce":          strings.Repeat("n", 4<<10+1),
		"login_hint":     strings.Repeat("h", 4<<10+1),
		"acr_values":     strings.Repeat("a", 4<<10+1),
		"scope":          strings.Repeat("openid ", 600),
		"id_token_hint":  strings.Repeat("i", 16<<10+1),
		"code_challenge": strings.Repeat("c", 129),
		"dpop_jkt":       strings.Repeat("j", 129),
		"max_age":        strings.Repeat("0", 32) + "1",
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, server.ProfileFAPISecurity, false)
			_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
				HTTP: server.FormRequest{Parameters: plainFormParametersWith(t, h.clientAssertion(t), map[string]string{name: value})},
			})
			if err == nil {
				t.Fatalf("a %d-byte %s was accepted", len(value), name)
			}
			if code := serverErrorCode(t, err); code != server.ErrorInvalidRequest {
				t.Fatalf("error = %v, want invalid_request", code)
			}
			if len(h.transactions.records) != 0 {
				t.Fatalf("stored %d pushed requests, want none", len(h.transactions.records))
			}
		})
	}
}

// TestPushAuthorizationRequestAcceptsCoreParametersAtTheirBound: a
// value exactly at its bound is still accepted.
func TestPushAuthorizationRequestAcceptsCoreParametersAtTheirBound(t *testing.T) {
	for name, value := range map[string]string{
		"state":      strings.Repeat("s", 4<<10),
		"nonce":      strings.Repeat("n", 4<<10),
		"login_hint": strings.Repeat("h", 4<<10),
		"max_age":    strings.Repeat("0", 31) + "1",
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, server.ProfileFAPISecurity, false)
			if _, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
				HTTP: server.FormRequest{Parameters: plainFormParametersWith(t, h.clientAssertion(t), map[string]string{name: value})},
			}); err != nil {
				t.Fatalf("PushAuthorizationRequest: %v", err)
			}
		})
	}
}

// TestPushAuthorizationRequestBoundsRequestObjectParameterSizes: the
// same bounds apply to a request object's members.
func TestPushAuthorizationRequestBoundsRequestObjectParameterSizes(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	params := standardAuthParams(t)
	params["state"] = jsonRaw(t, strings.Repeat("s", 4<<10+1))
	_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_assertion", h.clientAssertion(t)),
			formParam("client_assertion_type", clientassertion.AssertionType),
			formParam("request", h.requestObject(t, params)),
		}},
	})
	if err == nil {
		t.Fatal("a request object with an overlong state was accepted")
	}
	if code := serverErrorCode(t, err); code != server.ErrorInvalidRequest {
		t.Fatalf("error = %v, want invalid_request", code)
	}
}

// TestPushAuthorizationRequestTrimsOverlongPresentationPreferences:
// ui_locales, claims_locales and display never fail a request (OIDC
// Core §15.1), so an overlong one isn't refused: the stored request
// keeps only what the interaction would read from it.
func TestPushAuthorizationRequestTrimsOverlongPresentationPreferences(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, false)
	padding := strings.Repeat(" not_a_tag!", 20<<10)
	push, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: plainFormParametersWith(t, h.clientAssertion(t), map[string]string{
			"ui_locales":     "fr-CA en" + padding,
			"claims_locales": strings.TrimSpace(padding),
			"display":        "popup" + padding,
		})},
	})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
	if size := len(h.transactions.records[0].Request); size > 4<<10 {
		t.Fatalf("stored request is %d bytes, want the preferences trimmed", size)
	}
	stored := storedParameters(t, h.transactions.records[0])
	assertStoredString(t, stored, "ui_locales", "fr-CA en")
	for _, name := range []string{"claims_locales", "display"} {
		if raw, ok := stored[name]; ok {
			t.Fatalf("stored %s = %s, want it removed", name, raw)
		}
	}
	action, err := h.server.BeginAuthorization(context.Background(), server.BeginAuthorizationRequest{RequestURI: push.RequestURI.String(), ClientID: testClientID})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	interaction := action.(server.InteractionRequired).Interaction
	if !slices.Equal(interaction.UILocales, []string{"fr-CA", "en"}) || interaction.ClaimsLocales != nil || interaction.Display != "" {
		t.Fatalf("UILocales %q, ClaimsLocales %q, Display %q; want [fr-CA en], none, none", interaction.UILocales, interaction.ClaimsLocales, interaction.Display)
	}
}

func assertStoredString(t *testing.T, stored map[string]json.RawMessage, name, want string) {
	t.Helper()
	var got string
	if err := json.Unmarshal(stored[name], &got); err != nil || got != want {
		t.Fatalf("stored %s = %s, want %q", name, stored[name], want)
	}
}

// pushForInteractions pushes a request carrying a state at its bound,
// returning its request_uri.
func pushForInteractions(t *testing.T, h harness) string {
	t.Helper()
	push, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: plainFormParametersWith(t, h.clientAssertion(t), map[string]string{"state": strings.Repeat("s", 4<<10)})},
	})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
	return push.RequestURI.String()
}

// TestBeginAuthorizationBoundsInteractionsPerRequestURI: every
// interaction BeginAuthorization begins stores its own copy of the
// pushed request, so one request_uri begins at most eight; beyond that
// it's refused with invalid_request_uri and nothing more is stored.
// Another request_uri is unaffected.
func TestBeginAuthorizationBoundsInteractionsPerRequestURI(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, false)
	requestURI := pushForInteractions(t, h)
	const gets = 40
	begun := 0
	for i := range gets {
		action, err := h.server.BeginAuthorization(context.Background(), server.BeginAuthorizationRequest{RequestURI: requestURI, ClientID: testClientID})
		if err != nil {
			t.Fatalf("GET %d: %v", i, err)
		}
		switch a := action.(type) {
		case server.InteractionRequired:
			begun++
		case server.LocalErrorResponse:
			if a.Error.Code() != server.ErrorInvalidRequestURI {
				t.Fatalf("GET %d: error = %v, want invalid_request_uri", i, a.Error.Code())
			}
		default:
			t.Fatalf("GET %d: action = %T", i, action)
		}
	}
	if begun != 8 {
		t.Fatalf("%d GETs began %d interactions, want 8", gets, begun)
	}
	h.transactions.mu.Lock()
	stored := len(h.transactions.byHandle)
	h.transactions.mu.Unlock()
	if stored != 8 {
		t.Fatalf("%d GETs stored %d interaction records, want 8", gets, stored)
	}

	other := pushForInteractions(t, h)
	action, err := h.server.BeginAuthorization(context.Background(), server.BeginAuthorizationRequest{RequestURI: other, ClientID: testClientID})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	if _, ok := action.(server.InteractionRequired); !ok {
		t.Fatalf("another request_uri: action = %T, want InteractionRequired", action)
	}
}

// unavailableInteractionSlots is a replay store that can't answer for
// the interaction slots BeginAuthorization records, and records every
// other use as fakeReplayStore does.
type unavailableInteractionSlots struct{ fakeReplayStore }

func (u *unavailableInteractionSlots) UseOnce(ctx context.Context, use storage.ReplayUse) error {
	if use.Namespace == "server:authorization-interaction" {
		return errors.Join(storage.ErrStoreUnavailable, errors.New("connection refused"))
	}
	return u.fakeReplayStore.UseOnce(ctx, use)
}

// TestBeginAuthorizationInteractionSlotStoreUnavailable: when the
// replay store can't record the interaction, BeginAuthorization answers
// server_error and begins nothing, rather than refusing the request_uri.
func TestBeginAuthorizationInteractionSlotStoreUnavailable(t *testing.T) {
	transactions := &fakeTransactionStore{}
	h := newHarnessWithBackchannelOptions(t, memstore.NewBackchannelAuthenticationStore(), nil, func(d *server.Dependencies) {
		d.Replay = &unavailableInteractionSlots{}
		d.Transactions = transactions
	})
	push, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: plainFormParameters(t, h.clientAssertion(t), nil)},
	})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
	action, err := h.server.BeginAuthorization(context.Background(), server.BeginAuthorizationRequest{RequestURI: push.RequestURI.String(), ClientID: testClientID})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	le, ok := action.(server.LocalErrorResponse)
	if !ok || le.Error.Code() != server.ErrorServerError {
		t.Fatalf("action = %#v, want a server_error LocalErrorResponse", action)
	}
	if n := len(transactions.byHandle); n != 0 {
		t.Fatalf("stored %d interaction records, want none", n)
	}
}

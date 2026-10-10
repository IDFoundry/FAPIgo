package server_test

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/server"
)

// TestInteractionCarriesPrompt covers OIDC Core §3.1.2.1's prompt
// reaching the application: each value once, in the order sent, values
// another specification defines included, and kept by the encoding the
// application stores.
func TestInteractionCarriesPrompt(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)

	in := interactionFor(t, h, map[string]string{"prompt": "login consent login create"}).Interaction
	want := server.Prompt{server.PromptLogin, server.PromptConsent, "create"}
	if !slices.Equal(in.Prompt, want) {
		t.Fatalf("Prompt = %q, want %q", in.Prompt, want)
	}
	if !in.Prompt.Has(server.PromptLogin) || in.Prompt.Has(server.PromptNone) {
		t.Errorf("Has(login) = %v, Has(none) = %v; want true, false", in.Prompt.Has(server.PromptLogin), in.Prompt.Has(server.PromptNone))
	}

	none := interactionFor(t, h, map[string]string{"prompt": "none"}).Interaction
	if !slices.Equal(none.Prompt, server.Prompt{server.PromptNone}) {
		t.Errorf("prompt=none: Prompt = %q", none.Prompt)
	}
	if absent := interactionFor(t, h, nil).Interaction; absent.Prompt != nil {
		t.Errorf("no prompt: Prompt = %q, want nil", absent.Prompt)
	}

	text, err := in.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}
	restored, err := server.ParseInteractionRequest(string(text))
	if err != nil {
		t.Fatalf("ParseInteractionRequest: %v", err)
	}
	if !slices.Equal(restored.Prompt, want) {
		t.Errorf("restored Prompt = %q, want %q", restored.Prompt, want)
	}
}

// TestPushAuthorizationRequestRejectsPromptNoneWithAnotherValue covers
// OIDC Core §3.1.2.1: "If this parameter contains none with any other
// value, an error is returned."
func TestPushAuthorizationRequestRejectsPromptNoneWithAnotherValue(t *testing.T) {
	for _, value := range []string{"none login", "consent none", "none select_account", "none create"} {
		t.Run(value, func(t *testing.T) {
			h := newHarness(t, server.ProfileFAPISecurity, true)
			_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
				HTTP: server.FormRequest{Parameters: plainFormParameters(t, h.clientAssertion(t), map[string]string{"prompt": value})},
			})
			if code := serverErrorCode(t, err); code != server.ErrorInvalidRequest {
				t.Fatalf("prompt=%q: error code %q, want %q", value, code, server.ErrorInvalidRequest)
			}
		})
	}
	for _, value := range []string{"none", "none none", "login consent", ""} {
		t.Run("accepts "+value, func(t *testing.T) {
			h := newHarness(t, server.ProfileFAPISecurity, true)
			if _, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
				HTTP: server.FormRequest{Parameters: plainFormParameters(t, h.clientAssertion(t), map[string]string{"prompt": value})},
			}); err != nil {
				t.Fatalf("prompt=%q: %v", value, err)
			}
		})
	}
}

// TestCompleteAuthorizationInteractionNeeded covers answering a
// prompt=none the application can't satisfy: each InteractionNeed is
// sent to the client as its OIDC Core §3.1.2.6 error, with no code
// issued, and a value that isn't one is a local server error.
func TestCompleteAuthorizationInteractionNeeded(t *testing.T) {
	for need, code := range map[server.InteractionNeed]string{
		server.NeedLogin:            "login_required",
		server.NeedConsent:          "consent_required",
		server.NeedAccountSelection: "account_selection_required",
		server.NeedInteraction:      "interaction_required",
	} {
		t.Run(code, func(t *testing.T) { runInteractionNeededCase(t, need, code) })
	}

	t.Run("not an InteractionNeed", func(t *testing.T) {
		h := newHarness(t, server.ProfileFAPISecurity, true)
		handle := beginInteraction(t, h)
		result, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
			Handle: handle, Result: server.InteractionNeeded(server.InteractionNeed(99), ""),
		})
		if err != nil {
			t.Fatalf("CompleteAuthorization: %v", err)
		}
		local, ok := result.(server.AuthorizationLocalError)
		if !ok || local.Error.Code() != server.ErrorServerError {
			t.Fatalf("result = %#v, want a server_error AuthorizationLocalError", result)
		}
	})
}

// runInteractionNeededCase completes an interaction with
// InteractionNeeded(need) and checks the client is sent code, with the
// reason and no authorization code.
func runInteractionNeededCase(t *testing.T, need server.InteractionNeed, code string) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	handle := beginInteraction(t, h)
	result, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
		Handle: handle, Result: server.InteractionNeeded(need, "no session"),
	})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	redirect, ok := result.(server.AuthorizationRedirect)
	if !ok {
		t.Fatalf("result = %T, want server.AuthorizationRedirect", result)
	}
	dest := redirect.Destination().URL()
	query := dest.Query()
	if got := query.Get("error"); got != code {
		t.Fatalf("error = %q, want %q", got, code)
	}
	if got := query.Get("error_description"); got != "no session" {
		t.Errorf("error_description = %q, want the reason", got)
	}
	if query.Has("code") || len(h.grants.all()) != 0 {
		t.Fatalf("a code was issued for %s", code)
	}
}

// forgetPushedAt rewrites every pending interaction's stored request
// without pushed_at, as a record written before it existed is.
func forgetPushedAt(t *testing.T, h harness) {
	t.Helper()
	h.transactions.mu.Lock()
	defer h.transactions.mu.Unlock()
	if len(h.transactions.byHandle) == 0 {
		t.Fatal("no pending interaction to rewrite")
	}
	for handle, pending := range h.transactions.byHandle {
		var record map[string]json.RawMessage
		if err := json.Unmarshal(pending.interaction.Request, &record); err != nil {
			t.Fatal(err)
		}
		if _, ok := record["pushed_at"]; !ok {
			t.Fatal("the stored request has no pushed_at to forget")
		}
		delete(record, "pushed_at")
		raw, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		pending.interaction.Request = raw
		h.transactions.byHandle[handle] = pending
	}
}

// TestCompleteAuthorizationEnforcesPromptLogin covers OIDC Core
// §3.1.2.1's prompt=login: an authentication from before the request
// was pushed (less Limits.MaxClockSkew, 5s in the harness) answers the
// client with login_required rather than a code; other prompts and a
// record written before the push time was kept aren't checked.
func TestCompleteAuthorizationEnforcesPromptLogin(t *testing.T) {
	for _, tc := range []promptLoginCase{
		{name: "authenticated for the request", prompt: "login", authAgo: 0},
		{name: "authenticated within the skew", prompt: "login", authAgo: 4 * time.Second},
		{name: "existing session", prompt: "login", authAgo: time.Minute, wantError: "login_required"},
		{name: "just past the skew", prompt: "login", authAgo: 6 * time.Second, wantError: "login_required"},
		{name: "with consent too", prompt: "consent login", authAgo: time.Hour, wantError: "login_required"},
		{name: "record without push time", prompt: "login", authAgo: time.Hour, legacy: true},
		{name: "prompt=consent", prompt: "consent", authAgo: time.Hour},
		{name: "prompt=none", prompt: "none", authAgo: time.Hour},
		{name: "no prompt", authAgo: time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) { runPromptLoginCase(t, tc) })
	}
}

// promptLoginCase is one TestCompleteAuthorizationEnforcesPromptLogin
// case.
type promptLoginCase struct {
	name      string
	prompt    string
	authAgo   time.Duration
	legacy    bool
	wantError string
}

// runPromptLoginCase pushes tc's request, completes it with an
// authentication tc.authAgo before now and checks the redirect.
func runPromptLoginCase(t *testing.T, tc promptLoginCase) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	extra := map[string]string{}
	if tc.prompt != "" {
		extra["prompt"] = tc.prompt
	}
	handle := interactionFor(t, h, extra).Handle
	if tc.legacy {
		forgetPushedAt(t, h)
	}
	result := authorizedAt(t, h.now.Add(-tc.authAgo))
	completed, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{Handle: handle, Result: result})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	redirect, ok := completed.(server.AuthorizationRedirect)
	if !ok {
		t.Fatalf("result = %T, want a redirect", completed)
	}
	dest := redirect.Destination().URL()
	q := dest.Query()
	if q.Get("error") != tc.wantError {
		t.Errorf("error = %q (%s), want %q", q.Get("error"), q.Get("error_description"), tc.wantError)
	}
	if (q.Get("code") != "") != (tc.wantError == "") {
		t.Errorf("code present = %v, want %v", q.Get("code") != "", tc.wantError == "")
	}
	if tc.wantError != "" && len(h.grants.all()) != 0 {
		t.Error("a code was stored for a refused completion")
	}
}

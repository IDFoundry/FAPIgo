package server_test

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/server"
)

// interactionFor pushes and begins an authorization with extra plain
// parameters, returning the interaction.
func interactionFor(t *testing.T, h harness, extra map[string]string) server.InteractionRequired {
	t.Helper()
	required, ok := pushAndBegin(t, h, extra).(server.InteractionRequired)
	if !ok {
		t.Fatal("BeginAuthorization didn't require an interaction")
	}
	return required
}

func TestInteractionCarriesACRValuesAndMaxAge(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)

	in := interactionFor(t, h, map[string]string{"acr_values": "urn:example:strong urn:example:basic", "max_age": "300"}).Interaction
	if !slices.Equal(in.ACRValues, []string{"urn:example:strong", "urn:example:basic"}) {
		t.Errorf("ACRValues = %q, want both, most preferred first", in.ACRValues)
	}
	if !in.HasMaxAge || in.MaxAge != 300*time.Second {
		t.Errorf("MaxAge = %v (HasMaxAge %v), want 5m0s", in.MaxAge, in.HasMaxAge)
	}

	zero := interactionFor(t, h, map[string]string{"max_age": "0"}).Interaction
	if !zero.HasMaxAge || zero.MaxAge != 0 {
		t.Errorf("max_age=0: MaxAge = %v (HasMaxAge %v), want 0 and set", zero.MaxAge, zero.HasMaxAge)
	}

	none := interactionFor(t, h, nil).Interaction
	if none.HasMaxAge || none.ACRValues != nil {
		t.Errorf("no max_age or acr_values: HasMaxAge %v, ACRValues %q; want neither", none.HasMaxAge, none.ACRValues)
	}

	// The encoding the application stores keeps both.
	text, err := in.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}
	restored, err := server.ParseInteractionRequest(string(text))
	if err != nil {
		t.Fatalf("ParseInteractionRequest: %v", err)
	}
	if !slices.Equal(restored.ACRValues, in.ACRValues) || restored.MaxAge != in.MaxAge || !restored.HasMaxAge {
		t.Errorf("restored ACRValues %q, MaxAge %v (HasMaxAge %v); want the original's", restored.ACRValues, restored.MaxAge, restored.HasMaxAge)
	}
	text, err = zero.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText(max_age=0): %v", err)
	}
	if restored, err = server.ParseInteractionRequest(string(text)); err != nil || !restored.HasMaxAge || restored.MaxAge != 0 {
		t.Errorf("restored max_age=0: MaxAge %v (HasMaxAge %v), err %v; want 0 and set", restored.MaxAge, restored.HasMaxAge, err)
	}
}

// TestRequestObjectMaxAgeIsANumber covers max_age as a JSON number, the
// shape a signed request object carries it in.
func TestRequestObjectMaxAgeIsANumber(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	params := standardAuthParams(t)
	params["max_age"] = json.RawMessage("600")
	pushResult, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_assertion", h.clientAssertion(t)),
			formParam("client_assertion_type", clientassertion.AssertionType),
			formParam("request", h.requestObject(t, params)),
		}},
	})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
	action, err := h.server.BeginAuthorization(context.Background(), server.BeginAuthorizationRequest{
		RequestURI: pushResult.RequestURI.String(), ClientID: testClientID,
	})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	in := action.(server.InteractionRequired).Interaction
	if !in.HasMaxAge || in.MaxAge != 10*time.Minute {
		t.Errorf("MaxAge = %v (HasMaxAge %v), want 10m0s", in.MaxAge, in.HasMaxAge)
	}
}

func TestPushAuthorizationRequestRejectsMalformedMaxAge(t *testing.T) {
	for _, value := range []string{"-1", "1.5", "five", "", "99999999999999999999"} {
		t.Run(value, func(t *testing.T) {
			h := newHarness(t, server.ProfileFAPISecurity, true)
			_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
				HTTP: server.FormRequest{Parameters: plainFormParameters(t, h.clientAssertion(t), map[string]string{"max_age": value})},
			})
			if code := serverErrorCode(t, err); code != server.ErrorInvalidRequest {
				t.Fatalf("max_age=%q: error code %q, want %q", value, code, server.ErrorInvalidRequest)
			}
		})
	}
}

// authorizedAt is an Authorize result whose user authenticated at
// authTime.
func authorizedAt(t *testing.T, authTime time.Time) server.InteractionResult {
	t.Helper()
	subjectID, err := server.NewSubjectID("user-1")
	if err != nil {
		t.Fatal(err)
	}
	subject, err := server.NewAuthenticatedSubject(subjectID)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := server.NewAuthenticationContext(authTime, "urn:example:strong", []string{"pwd"})
	if err != nil {
		t.Fatal(err)
	}
	return server.Authorize(subject, auth, server.GrantedAuthorization{Scope: []string{"openid", "accounts"}})
}

// TestCompleteAuthorizationEnforcesMaxAge covers OIDC Core §3.1.2.1: an
// authentication older than max_age answers the client with
// login_required rather than a code.
func TestCompleteAuthorizationEnforcesMaxAge(t *testing.T) {
	for _, tc := range []struct {
		name      string
		maxAge    string
		authAgo   time.Duration
		wantError string
	}{
		{"within max_age", "300", time.Minute, ""},
		{"older than max_age", "300", 10 * time.Minute, "login_required"},
		{"max_age=0, just authenticated", "0", 0, ""},
		{"max_age=0, authenticated earlier", "0", time.Minute, "login_required"},
		{"no max_age, long ago", "", 24 * time.Hour, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, server.ProfileFAPISecurity, true)
			extra := map[string]string{}
			if tc.maxAge != "" {
				extra["max_age"] = tc.maxAge
			}
			handle := interactionFor(t, h, extra).Handle
			result, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
				Handle: handle, Result: authorizedAt(t, h.now.Add(-tc.authAgo)),
			})
			if err != nil {
				t.Fatalf("CompleteAuthorization: %v", err)
			}
			redirect, ok := result.(server.AuthorizationRedirect)
			if !ok {
				t.Fatalf("result = %T, want a redirect", result)
			}
			dest := redirect.Destination().URL()
			q := dest.Query()
			if q.Get("error") != tc.wantError {
				t.Errorf("error = %q, want %q", q.Get("error"), tc.wantError)
			}
			if (q.Get("code") != "") != (tc.wantError == "") {
				t.Errorf("code present = %v, want %v", q.Get("code") != "", tc.wantError == "")
			}
		})
	}
}

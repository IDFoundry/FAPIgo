package server_test

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/server"
)

// TestInteractionCarriesLocalesAndDisplay: ui_locales, claims_locales
// and display reach the interaction, and survive its encoding.
func TestInteractionCarriesLocalesAndDisplay(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	in := interactionFor(t, h, map[string]string{
		"ui_locales":     "fr-CA fr en",
		"claims_locales": "de en-GB",
		"display":        "popup",
	}).Interaction
	check := func(t *testing.T, in server.InteractionRequest) {
		t.Helper()
		if want := []string{"fr-CA", "fr", "en"}; !slices.Equal(in.UILocales, want) {
			t.Errorf("UILocales = %q, want %q", in.UILocales, want)
		}
		if want := []string{"de", "en-GB"}; !slices.Equal(in.ClaimsLocales, want) {
			t.Errorf("ClaimsLocales = %q, want %q", in.ClaimsLocales, want)
		}
		if in.Display != server.DisplayPopup {
			t.Errorf("Display = %q, want popup", in.Display)
		}
	}
	check(t, in)

	text, err := in.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}
	restored, err := server.ParseInteractionRequest(string(text))
	if err != nil {
		t.Fatalf("ParseInteractionRequest: %v", err)
	}
	check(t, restored)
}

// TestRequestObjectCarriesLocalesAndDisplay covers the same parameters
// in a signed request object.
func TestRequestObjectCarriesLocalesAndDisplay(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	params := standardAuthParams(t)
	params["ui_locales"] = json.RawMessage(`"ja en"`)
	params["display"] = json.RawMessage(`"touch"`)
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
	if want := []string{"ja", "en"}; !slices.Equal(in.UILocales, want) {
		t.Errorf("UILocales = %q, want %q", in.UILocales, want)
	}
	if in.Display != server.DisplayTouch {
		t.Errorf("Display = %q, want touch", in.Display)
	}
}

// TestMalformedLocalesAndDisplayAreDropped: OIDC Core §15.1 has these
// never cause an error, so a malformed value is dropped instead, and a
// long list is cut short rather than carried whole.
func TestMalformedLocalesAndDisplayAreDropped(t *testing.T) {
	many := make([]string, 40)
	for i := range many {
		many[i] = "x" + strings.Repeat("a", i%7) + "-" + string(rune('a'+i%26))
	}
	for name, tc := range map[string]struct {
		uiLocales, display string
		wantUI             []string
		wantDisplay        server.Display
	}{
		"unknown display":        {"en", "fullscreen", []string{"en"}, ""},
		"miscased display":       {"en", "Popup", []string{"en"}, ""},
		"bad tags dropped":       {"en_US fr-- 1en é ok-123 " + strings.Repeat("a", 9) + " zh-Hant-TW", "wap", []string{"ok-123", "zh-Hant-TW"}, server.DisplayWAP},
		"too long a tag":         {"en-" + strings.Repeat("abcdefgh-", 4) + "x", "page", nil, server.DisplayPage},
		"repeats, ignoring case": {"en EN en-gb EN-GB", "", []string{"en", "en-gb"}, ""},
		"only whitespace":        {"   ", "", nil, ""},
		"more than sixteen tags": {strings.Join(many, " "), "", many[:16], ""},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, server.ProfileFAPISecurity, true)
			extra := map[string]string{"ui_locales": tc.uiLocales}
			if tc.display != "" {
				extra["display"] = tc.display
			}
			in := interactionFor(t, h, extra).Interaction
			if !slices.Equal(in.UILocales, tc.wantUI) {
				t.Errorf("UILocales = %q, want %q", in.UILocales, tc.wantUI)
			}
			if in.Display != tc.wantDisplay {
				t.Errorf("Display = %q, want %q", in.Display, tc.wantDisplay)
			}
		})
	}
}

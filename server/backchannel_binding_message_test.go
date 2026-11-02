package server_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// TestRequireBindingMessage: FAPI-CIBA §5.2.2 — with
// Config.RequireBindingMessage, a request without binding_message is
// refused with invalid_request, and one whose binding_message shows
// nothing (empty, only spaces) with invalid_binding_message, before
// it's acknowledged; one with a visible message, and any request
// without the setting, is accepted.
func TestRequireBindingMessage(t *testing.T) {
	const absent = "\x00absent"
	for name, tc := range map[string]struct {
		require  bool
		message  string
		wantCode server.ErrorCode
	}{
		"required, missing":           {true, absent, server.ErrorInvalidRequest},
		"required, present":           {true, "Order 1042", ""},
		"required, empty":             {true, "", server.ErrorInvalidBindingMessage},
		"required, spaces":            {true, "     ", server.ErrorInvalidBindingMessage},
		"required, ideographic space": {true, "\u3000", server.ErrorInvalidBindingMessage},
		"required, combining only":    {true, "\u0301\u0301", server.ErrorInvalidBindingMessage},
		"default, missing":            {false, absent, ""},
		"default, empty":              {false, "", ""},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarnessWithBackchannelConfig(t, memstore.NewBackchannelAuthenticationStore(), func(c *server.Config) { c.RequireBindingMessage = tc.require })
			params := standardBackchannelParams(t)
			if tc.message == absent {
				delete(params, "binding_message")
			} else {
				params["binding_message"] = jsonRaw(t, tc.message)
			}
			action, err := h.server.BeginBackchannelAuthentication(context.Background(), server.BeginBackchannelAuthenticationRequest{
				HTTP: server.FormRequest{Parameters: backchannelFormParams(h.clientAssertion(t), h.backchannelRequestObject(t, params))},
			})
			if err != nil {
				t.Fatalf("BeginBackchannelAuthentication: %v", err)
			}
			assertBindingMessageOutcome(t, action, tc.wantCode)
		})
	}
}

// TestBindingMessageRefusesFormatCharacters: a binding_message holding
// a Unicode format character (category Cf) — a bidi control that
// reorders what the authentication device shows, or a zero-width
// character that hides part of it — is refused with
// invalid_binding_message (CIBA §13), whether or not
// Config.RequireBindingMessage is set.
func TestBindingMessageRefusesFormatCharacters(t *testing.T) {
	for name, msg := range map[string]string{
		"right-to-left override":  "\u202eTCS4W",
		"left-to-right embedding": "W4SCT\u202a",
		"right-to-left isolate":   "W4\u2067SCT\u2069",
		"zero-width space":        "W4S\u200bCT",
		"zero-width only":         "\u200b\u200b",
		"zero-width joiner":       "W4\u200dSCT",
		"word joiner only":        "\u2060\u2060",
		"byte order mark":         "\xef\xbb\xbfW4SCT",
		"soft hyphen":             "W4\u00adSCT",
	} {
		for _, require := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s, required %v", name, require), func(t *testing.T) {
				h := newHarnessWithBackchannelConfig(t, memstore.NewBackchannelAuthenticationStore(), func(c *server.Config) { c.RequireBindingMessage = require })
				params := standardBackchannelParams(t)
				params["binding_message"] = jsonRaw(t, msg)
				action, err := h.server.BeginBackchannelAuthentication(context.Background(), server.BeginBackchannelAuthenticationRequest{
					HTTP: server.FormRequest{Parameters: backchannelFormParams(h.clientAssertion(t), h.backchannelRequestObject(t, params))},
				})
				if err != nil {
					t.Fatalf("BeginBackchannelAuthentication: %v", err)
				}
				assertBindingMessageOutcome(t, action, server.ErrorInvalidBindingMessage)
			})
		}
	}
}

// assertBindingMessageOutcome checks action is refused with wantCode,
// or accepted when wantCode is empty.
func assertBindingMessageOutcome(t *testing.T, action server.BackchannelAuthenticationAction, wantCode server.ErrorCode) {
	t.Helper()
	le, refused := action.(server.BackchannelAuthenticationLocalError)
	if refused != (wantCode != "") {
		t.Fatalf("action = %T, want refused with %q", action, wantCode)
	}
	if refused && le.Error.Code() != wantCode {
		t.Fatalf("error = %v, want %v", le.Error.Code(), wantCode)
	}
}

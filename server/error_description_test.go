package server_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/idfoundry/fapigo/internal/httperror"
	"github.com/idfoundry/fapigo/server"
)

// TestCompleteAuthorizationDropsReasonOutsideErrorText: an application's
// reason becomes error_description only when it's RFC 6749 error text
// (printable ASCII without '"' or '\'); otherwise the error goes out
// without one, as server.NewError drops such a description.
func TestCompleteAuthorizationDropsReasonOutsideErrorText(t *testing.T) {
	for name, tc := range map[string]struct {
		result   server.InteractionResult
		wantDesc string
	}{
		"deny with error text":                {server.Deny("user declined consent"), "user declined consent"},
		"deny with a quote":                   {server.Deny(`declined "payments"`), ""},
		"deny with a newline":                 {server.Deny("declined\nINJECTED"), ""},
		"deny with non-ASCII":                 {server.Deny("décliné"), ""},
		"authentication failed with CRLF":     {server.AuthenticationFailed("bad\r\npassword"), ""},
		"interaction needed with a backslash": {server.InteractionNeeded(server.NeedLogin, `C:\path`), ""},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, server.ProfileFAPISecurity, true)
			handle := beginInteraction(t, h)
			res, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{Handle: handle, Result: tc.result})
			if err != nil {
				t.Fatalf("CompleteAuthorization: %v", err)
			}
			redirect, ok := res.(server.AuthorizationRedirect)
			if !ok {
				t.Fatalf("result = %T, want AuthorizationRedirect", res)
			}
			destURL := redirect.Destination().URL()
			q := destURL.Query()
			if q.Get("error") == "" {
				t.Fatalf("destination %q has no error", redirect.Destination().String())
			}
			if got, present := q.Get("error_description"), q.Has("error_description"); got != tc.wantDesc || present != (tc.wantDesc != "") {
				t.Fatalf("error_description = %q (present %v), want %q", got, present, tc.wantDesc)
			}
		})
	}
}

// TestBuildAuthorizationErrorRedirectChecksErrorText: a description
// outside RFC 6749 error text is dropped, and an error code outside it
// is refused, since the caller supplies both.
func TestBuildAuthorizationErrorRedirectChecksErrorText(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	ctx := context.Background()

	dest, err := h.server.BuildAuthorizationErrorRedirect(ctx, testRegisteredClient(t), testRedirectURI, "s", "invalid_request", "bad\r\nINJECTED")
	if err != nil {
		t.Fatalf("BuildAuthorizationErrorRedirect: %v", err)
	}
	destURL := dest.URL()
	if q := destURL.Query(); q.Has("error_description") || q.Get("error") != "invalid_request" {
		t.Fatalf("destination = %q, want invalid_request with no error_description", dest.String())
	}

	if _, err := h.server.BuildAuthorizationErrorRedirect(ctx, testRegisteredClient(t), testRedirectURI, "s", "invalid\"request", "x"); err == nil {
		t.Fatal("BuildAuthorizationErrorRedirect with a quote in the error code = nil error, want error")
	}
}

// hostileClaimName is a claim name carrying every kind of byte RFC 6749
// §5.2 keeps out of error_description — a double quote, a backslash, a
// non-ASCII letter, a line separator and a control character — plus a
// marker to find it by if it were reflected.
const hostileClaimName = "evil\"\\é \u0001MARKER"

// hostileClaims are "claims" parameters each refused for a reason that
// involves client-chosen text, which must stay out of the description.
var hostileClaims = map[string]string{
	"claim request not an object":  `{"id_token":{"` + jsonEscape(hostileClaimName) + `":5}}`,
	"userinfo claim not an object": `{"userinfo":{"` + jsonEscape(hostileClaimName) + `":"x"}}`,
	// encoding/json folds U+017F (long s) to "s", so these case variants
	// carry a non-ASCII member name.
	"case-variant location":   `{"u\u017ferinfo":{}}`,
	"case-variant acr member": `{"id_token":{"acr":{"e\u017f\u017fential":true}}}`,
	"case-variant sub member": `{"id_token":{"sub":{"value\u017f":["x"]}}}`,
	"acr entry not an object": `{"id_token":{"acr":"MARKER"}}`,
	"sub values differ":       `{"id_token":{"sub":{"value":"a"}},"userinfo":{"sub":{"value":"MARKER"}}}`,
	"claims not an object":    `"MARKER"`,
}

func jsonEscape(s string) string {
	b, _ := json.Marshal(s)
	return string(b[1 : len(b)-1])
}

// assertPublicDescription checks e's description, as PublicDescription
// returns it and as WriteJSON sends it, is RFC 6749 §5.2 error text
// (or absent) and reflects nothing of the request.
func assertPublicDescription(t *testing.T, e *server.Error) {
	t.Helper()
	desc := e.PublicDescription()
	if desc != "" && !httperror.IsErrorText(desc) {
		t.Errorf("PublicDescription() = %q, outside RFC 6749 §5.2's characters", desc)
	}
	if strings.Contains(desc, "MARKER") {
		t.Errorf("PublicDescription() = %q reflects request input", desc)
	}
	rec := httptest.NewRecorder()
	e.WriteJSON(rec)
	var body struct {
		ErrorDescription string `json:"error_description"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body %s: %v", rec.Body.Bytes(), err)
	}
	if body.ErrorDescription != desc {
		t.Errorf("body error_description = %q, want %q", body.ErrorDescription, desc)
	}
}

// TestPARErrorDescriptionsAreErrorText: every "claims" parameter PAR
// refuses gets an error_description inside RFC 6749 §5.2's character
// set (%x20-21 / %x23-5B / %x5D-7E) that names nothing the client sent.
func TestPARErrorDescriptionsAreErrorText(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	for name, claims := range hostileClaims {
		t.Run(name, func(t *testing.T) {
			params := plainFormParameters(t, h.clientAssertion(t), map[string]string{"claims": claims})
			_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{HTTP: server.FormRequest{Parameters: params}})
			e, ok := err.(*server.Error)
			if !ok {
				t.Fatalf("err = %v, want a *server.Error", err)
			}
			if e.Code() != server.ErrorInvalidRequest {
				t.Fatalf("Code() = %q, want invalid_request", e.Code())
			}
			assertPublicDescription(t, e)
		})
	}
}

// TestBackchannelErrorDescriptionsAreErrorText is
// TestPARErrorDescriptionsAreErrorText for CIBA §13's error response.
func TestBackchannelErrorDescriptionsAreErrorText(t *testing.T) {
	h, _ := newHarnessWithBackchannel(t)
	for name, claims := range hostileClaims {
		t.Run(name, func(t *testing.T) {
			params := standardBackchannelParams(t)
			params["claims"] = json.RawMessage(claims)
			requestObj := h.backchannelRequestObject(t, params)
			action, err := h.server.BeginBackchannelAuthentication(context.Background(), server.BeginBackchannelAuthenticationRequest{
				HTTP: server.FormRequest{Parameters: backchannelFormParams(h.clientAssertion(t), requestObj)},
			})
			if err != nil {
				t.Fatal(err)
			}
			localErr, ok := action.(server.BackchannelAuthenticationLocalError)
			if !ok {
				t.Fatalf("action = %T, want BackchannelAuthenticationLocalError", action)
			}
			assertPublicDescription(t, localErr.Error)
		})
	}
}

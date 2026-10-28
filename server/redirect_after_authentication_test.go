package server_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/server"
)

// This file covers RFC 9700 §4.11.2 ("MUST always authenticate the user
// first ... before redirecting the user") and §4.16 ("Authorization
// servers MUST prevent clickjacking attacks"): an interaction nobody
// authenticated in can end without a redirect, the consent step can see
// the redirect URI, and authorization pages refuse to be framed.

// requireLocalError fails unless out is an AuthorizationLocalError with
// code, and returns its error.
func requireLocalError(t *testing.T, out server.AuthorizationResult, code server.ErrorCode) *server.Error {
	t.Helper()
	local, ok := out.(server.AuthorizationLocalError)
	if !ok {
		t.Fatalf("result = %T, want server.AuthorizationLocalError (no redirect)", out)
	}
	if local.Error.Code() != code {
		t.Fatalf("Error.Code() = %q, want %q", local.Error.Code(), code)
	}
	return local.Error
}

func TestCompleteAuthorizationDenyLocallyDoesNotRedirect(t *testing.T) {
	cases := map[string]struct {
		reason, want string
	}{
		"application's reason":         {"you declined before signing in", "you declined before signing in"},
		"no reason":                    {"", "the request was declined"},
		"reason outside RFC 6749 text": {"declined\r\nINJECTED", "the request was declined"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, server.ProfileFAPISecurity, true)
			handle := beginInteraction(t, h)
			out, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{Handle: handle, Result: server.DenyLocally(tc.reason)})
			if err != nil {
				t.Fatalf("CompleteAuthorization: %v", err)
			}
			got := requireLocalError(t, out, server.ErrorAccessDenied)
			if got.PublicDescription() != tc.want {
				t.Fatalf("PublicDescription() = %q, want %q", got.PublicDescription(), tc.want)
			}
			if got.HTTPStatus() != http.StatusForbidden {
				t.Fatalf("HTTPStatus() = %d, want %d", got.HTTPStatus(), http.StatusForbidden)
			}
			if len(h.grants.all()) != 0 {
				t.Fatalf("len(codes) = %d, want 0", len(h.grants.all()))
			}
			// The interaction is over: its handle can't be completed again,
			// with a redirecting result or any other.
			again, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{Handle: handle, Result: server.Deny("")})
			if err != nil {
				t.Fatalf("CompleteAuthorization (again): %v", err)
			}
			requireLocalError(t, again, server.ErrorInvalidRequest)
		})
	}
}

// TestCompleteBackchannelAuthenticationDenyLocallyIsDeny: nothing
// redirects in CIBA, so DenyLocally records a denial the client sees as
// access_denied, as Deny does.
func TestCompleteBackchannelAuthenticationDenyLocallyIsDeny(t *testing.T) {
	h, _ := newHarnessWithBackchannel(t)
	required := beginBackchannel(t, h, standardBackchannelParams(t))
	if err := h.server.CompleteBackchannelAuthentication(context.Background(), server.CompleteBackchannelAuthenticationRequest{
		Handle: required.Handle, Result: server.DenyLocally("user declined"),
	}); err != nil {
		t.Fatalf("CompleteBackchannelAuthentication: %v", err)
	}
	_, err := h.server.ExchangeBackchannelAuthentication(context.Background(), server.BackchannelTokenExchangeRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_assertion", h.clientAssertion(t)),
			formParam("client_assertion_type", clientassertion.AssertionType),
			formParam("grant_type", server.CIBAGrantType),
			formParam("auth_req_id", required.AuthReqID.String()),
		}},
		DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
	})
	if code := serverErrorCode(t, err); code != server.ErrorAccessDenied {
		t.Fatalf("error code = %q, want %q", code, server.ErrorAccessDenied)
	}
}

func TestBeginAuthorizationInteractionCarriesRedirectURI(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	required, ok := pushAndBegin(t, h, nil).(server.InteractionRequired)
	if !ok {
		t.Fatal("BeginAuthorization didn't require interaction")
	}
	if got := required.Interaction.RedirectURI.String(); got != testRedirectURI {
		t.Fatalf("Interaction.RedirectURI = %q, want %q", got, testRedirectURI)
	}

	// It survives the encoding an application keeps between the pages.
	text, err := required.Interaction.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}
	restored, err := server.ParseInteractionRequest(string(text))
	if err != nil {
		t.Fatalf("ParseInteractionRequest: %v", err)
	}
	if got := restored.RedirectURI.String(); got != testRedirectURI {
		t.Fatalf("restored RedirectURI = %q, want %q", got, testRedirectURI)
	}
}

func TestAuthorizationPageHeaders(t *testing.T) {
	want := map[string]string{
		"Content-Security-Policy": "frame-ancestors 'none'",
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "no-referrer",
		"Cache-Control":           "no-store",
	}
	handler := server.AuthorizationPageHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, "https://rp.example/cb", http.StatusSeeOther)
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/authorize", nil))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want the wrapped handler's %d", rec.Code, http.StatusSeeOther)
	}
	for name, value := range want {
		if got := rec.Header().Get(name); got != value {
			t.Errorf("%s = %q, want %q", name, got, value)
		}
	}
}

// TestAuthorizationPageHeadersLetsTheHandlerOverride: a page that must
// be framed by a particular origin sets its own policy.
func TestAuthorizationPageHeadersLetsTheHandlerOverride(t *testing.T) {
	const own = "frame-ancestors https://wallet.example"
	handler := server.AuthorizationPageHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Security-Policy", own)
		w.Header().Del("X-Frame-Options")
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/authorize", nil))
	if got := rec.Header().Get("Content-Security-Policy"); got != own {
		t.Fatalf("Content-Security-Policy = %q, want %q", got, own)
	}
	if got := rec.Header().Get("X-Frame-Options"); got != "" {
		t.Fatalf("X-Frame-Options = %q, want none", got)
	}
}

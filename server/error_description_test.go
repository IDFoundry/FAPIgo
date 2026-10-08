package server_test

import (
	"context"
	"testing"

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

package server_test

import (
	"context"
	"testing"

	"github.com/idfoundry/fapigo/server"
)

// TestParseInteractionHandleRoundTrip covers the whole point of
// ParseInteractionHandle: a handle reconstructed purely from its own
// wire value — as if read back from a consent-UI bridge's own
// distributed storage, on a different request than the one
// BeginAuthorization ran on — works identically to the original typed
// value when passed to CompleteAuthorization.
func TestParseInteractionHandleRoundTrip(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	original := beginInteraction(t, h)

	reconstructed, err := server.ParseInteractionHandle(original.String())
	if err != nil {
		t.Fatalf("ParseInteractionHandle: %v", err)
	}
	if reconstructed != original {
		t.Fatalf("ParseInteractionHandle round trip = %+v, want %+v", reconstructed, original)
	}

	result, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
		Handle: reconstructed, Result: authorizeResult(t),
	})
	if err != nil {
		t.Fatalf("CompleteAuthorization(reconstructed handle): %v", err)
	}
	if _, ok := result.(server.AuthorizationRedirect); !ok {
		t.Fatalf("result = %T, want server.AuthorizationRedirect", result)
	}
}

// TestParseInteractionHandleRejectsEmpty covers ParseInteractionHandle's
// one piece of validation: an empty value is always a caller bug (no
// wire value BeginAuthorization ever produces is empty), not a handle
// CompleteAuthorization could ever have accepted anyway.
func TestParseInteractionHandleRejectsEmpty(t *testing.T) {
	if _, err := server.ParseInteractionHandle(""); err == nil {
		t.Fatal("ParseInteractionHandle(\"\") = nil error, want error")
	}
}

// TestParseInteractionHandleUnrecognizedValueFailsAtComplete covers the
// documented contract: ParseInteractionHandle itself applies no format
// validation beyond rejecting empty — a value that was never a real
// handle is instead rejected by CompleteAuthorization, which reports an
// invalid handle via its own AuthorizationLocalError result, not the
// error return (see CompleteAuthorization's own doc comment: "the
// error return is reserved for failures outside the request itself").
func TestParseInteractionHandleUnrecognizedValueFailsAtComplete(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)

	bogus, err := server.ParseInteractionHandle("this-was-never-a-real-handle")
	if err != nil {
		t.Fatalf("ParseInteractionHandle: %v", err)
	}

	result, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
		Handle: bogus, Result: authorizeResult(t),
	})
	if err != nil {
		t.Fatalf("CompleteAuthorization(unrecognized handle): %v", err)
	}
	if _, ok := result.(server.AuthorizationLocalError); !ok {
		t.Fatalf("result = %T, want server.AuthorizationLocalError", result)
	}
}

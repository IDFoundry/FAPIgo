package server_test

import (
	"context"
	"testing"

	"github.com/idfoundry/fapigo/server"
)

// TestParseBackchannelAuthenticationHandleRoundTrip mirrors
// TestParseInteractionHandleRoundTrip for CIBA's own out-of-band
// authentication component: a handle reconstructed purely from its own
// wire value — as if read back from that component's own distributed
// storage, on a different request than the one
// BeginBackchannelAuthentication ran on — works identically to the
// original typed value when passed to CompleteBackchannelAuthentication.
func TestParseBackchannelAuthenticationHandleRoundTrip(t *testing.T) {
	h, _ := newHarnessWithBackchannel(t)
	required := beginBackchannel(t, h, standardBackchannelParams(t))

	reconstructed, err := server.ParseBackchannelAuthenticationHandle(required.Handle.String())
	if err != nil {
		t.Fatalf("ParseBackchannelAuthenticationHandle: %v", err)
	}
	if reconstructed != required.Handle {
		t.Fatalf("ParseBackchannelAuthenticationHandle round trip = %+v, want %+v", reconstructed, required.Handle)
	}

	subject, err := server.NewSubjectID("user-1")
	if err != nil {
		t.Fatalf("NewSubjectID: %v", err)
	}
	authenticated, err := server.NewAuthenticatedSubject(subject)
	if err != nil {
		t.Fatalf("NewAuthenticatedSubject: %v", err)
	}
	authCtx, err := server.NewAuthenticationContext(h.now, "acr-1", []string{"pwd"})
	if err != nil {
		t.Fatalf("NewAuthenticationContext: %v", err)
	}

	if err := h.server.CompleteBackchannelAuthentication(context.Background(), server.CompleteBackchannelAuthenticationRequest{
		Handle: reconstructed,
		Result: server.Authorize(authenticated, authCtx, server.GrantedAuthorization{Scope: []string{"openid", "accounts"}}),
	}); err != nil {
		t.Fatalf("CompleteBackchannelAuthentication(reconstructed handle): %v", err)
	}
}

// TestParseBackchannelAuthenticationHandleRejectsEmpty mirrors
// TestParseInteractionHandleRejectsEmpty.
func TestParseBackchannelAuthenticationHandleRejectsEmpty(t *testing.T) {
	if _, err := server.ParseBackchannelAuthenticationHandle(""); err == nil {
		t.Fatal("ParseBackchannelAuthenticationHandle(\"\") = nil error, want error")
	}
}

// TestParseBackchannelAuthenticationHandleUnrecognizedValueFailsAtComplete
// mirrors TestParseInteractionHandleUnrecognizedValueFailsAtComplete.
func TestParseBackchannelAuthenticationHandleUnrecognizedValueFailsAtComplete(t *testing.T) {
	h, _ := newHarnessWithBackchannel(t)

	bogus, err := server.ParseBackchannelAuthenticationHandle("this-was-never-a-real-handle")
	if err != nil {
		t.Fatalf("ParseBackchannelAuthenticationHandle: %v", err)
	}

	subject, err := server.NewSubjectID("user-1")
	if err != nil {
		t.Fatalf("NewSubjectID: %v", err)
	}
	authenticated, err := server.NewAuthenticatedSubject(subject)
	if err != nil {
		t.Fatalf("NewAuthenticatedSubject: %v", err)
	}
	authCtx, err := server.NewAuthenticationContext(h.now, "acr-1", []string{"pwd"})
	if err != nil {
		t.Fatalf("NewAuthenticationContext: %v", err)
	}

	if err := h.server.CompleteBackchannelAuthentication(context.Background(), server.CompleteBackchannelAuthenticationRequest{
		Handle: bogus,
		Result: server.Authorize(authenticated, authCtx, server.GrantedAuthorization{Scope: []string{"openid", "accounts"}}),
	}); err == nil {
		t.Fatal("CompleteBackchannelAuthentication(unrecognized handle) = nil error, want error")
	}
}

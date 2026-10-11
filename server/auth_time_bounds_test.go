package server_test

import (
	"context"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/server"
)

// TestNewAuthenticationContextRefusesPreEpochAuthTime: an ID token's
// auth_time counts seconds from the Unix epoch, so an authTime before
// it, including one a nanosecond after the zero time, can't be one.
func TestNewAuthenticationContextRefusesPreEpochAuthTime(t *testing.T) {
	for name, authTime := range map[string]time.Time{
		"zero plus 1ns":     time.Time{}.Add(time.Nanosecond),
		"just before epoch": time.Unix(0, 0).Add(-time.Second),
	} {
		if _, err := server.NewAuthenticationContext(authTime, "", nil); err == nil {
			t.Errorf("%s: NewAuthenticationContext succeeded, want an error", name)
		}
	}
	if _, err := server.NewAuthenticationContext(time.Unix(0, 0), "", nil); err != nil {
		t.Errorf("NewAuthenticationContext(the epoch): %v", err)
	}
}

// TestCompleteAuthorizationRefusesFutureAuthTime: an authentication
// time later than now (beyond the clock skew allowed) didn't happen —
// an embedder passing a session's expiry, say — and would otherwise
// pass max_age=0 and prompt=login as the freshest authentication
// possible. It's a server_error, with or without those parameters.
func TestCompleteAuthorizationRefusesFutureAuthTime(t *testing.T) {
	for name, extra := range map[string]map[string]string{
		"plain":        {},
		"max_age=0":    {"max_age": "0"},
		"prompt=login": {"prompt": "login"},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, server.ProfileFAPISecurity, true)
			handle := interactionFor(t, h, extra).Handle
			result, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
				Handle: handle, Result: authorizedAt(t, h.now.Add(365*24*time.Hour)),
			})
			if err != nil {
				t.Fatalf("CompleteAuthorization: %v", err)
			}
			local, ok := result.(server.AuthorizationLocalError)
			if !ok || local.Error.Code() != server.ErrorServerError {
				t.Fatalf("result = %#v, want a server_error local error", result)
			}
		})
	}
}

// TestCompleteAuthorizationAcceptsAuthTimeWithinSkew: an authentication
// time a little ahead of the server's clock, within MaxClockSkew, is the
// authenticating host's clock running fast, and is accepted.
func TestCompleteAuthorizationAcceptsAuthTimeWithinSkew(t *testing.T) {
	h := newHarness(t, server.ProfileFAPISecurity, true)
	handle := interactionFor(t, h, map[string]string{"max_age": "0"}).Handle
	result, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
		Handle: handle, Result: authorizedAt(t, h.now.Add(time.Second)),
	})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	redirect, ok := result.(server.AuthorizationRedirect)
	if !ok {
		t.Fatalf("result = %#v, want a redirect", result)
	}
	if dest := redirect.Destination().URL(); dest.Query().Get("code") == "" {
		t.Fatalf("result = %#v, want a redirect with a code", result)
	}
}

// TestCompleteBackchannelAuthenticationRefusesFutureAuthTime is CIBA's
// counterpart.
func TestCompleteBackchannelAuthenticationRefusesFutureAuthTime(t *testing.T) {
	h, _ := newHarnessWithBackchannel(t)
	required := beginBackchannel(t, h, standardBackchannelParams(t))
	err := h.server.CompleteBackchannelAuthentication(context.Background(), server.CompleteBackchannelAuthenticationRequest{
		Handle: required.Handle, Result: authorizedAt(t, h.now.Add(365*24*time.Hour)),
	})
	if serverErrorCode(t, err) != server.ErrorServerError {
		t.Fatalf("CompleteBackchannelAuthentication = %v, want server_error", err)
	}
}

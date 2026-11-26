package server

import (
	"errors"
	"fmt"
	"testing"

	"github.com/idfoundry/fapigo/storage"
)

// TestStaleBackchannelEntry: a listed request's inbox entry is stale
// when deciding it fails because it expired or because the store says
// it was already decided or holds no such request, and is kept for any
// other refusal, which may be an outage reported as a plain error.
func TestStaleBackchannelEntry(t *testing.T) {
	decided := fmt.Errorf("store: %w", storage.ErrBackchannelAuthenticationAlreadyDecided)
	gone := fmt.Errorf("store: %w", storage.ErrBackchannelAuthenticationNotFound)
	for _, tc := range []struct {
		name    string
		failure *Error
		want    bool
	}{
		{"expired", newError(ErrorExpiredToken, 400, "auth_req_id has expired", nil), true},
		{"already decided", newError(ErrorInvalidRequest, 400, "already decided", decided), true},
		{"gone", newError(ErrorInvalidRequest, 400, "unknown", gone), true},
		{"plain invalid_request", newError(ErrorInvalidRequest, 400, "refused", errors.New("store: refused")), false},
		{"server_error", newError(ErrorServerError, 500, "store outage", decided), false},
		{"server_error, gone", newError(ErrorServerError, 500, "store outage", gone), false},
	} {
		if got := staleBackchannelEntry(tc.failure); got != tc.want {
			t.Errorf("%s: staleBackchannelEntry = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestGoneBackchannelRequest: a listed entry's request is gone, and the
// entry skipped, only when the lookup says its client is no longer
// registered or the store says it holds no such request; any other
// refusal, an outage, or an error that isn't the server's is not.
func TestGoneBackchannelRequest(t *testing.T) {
	gone := fmt.Errorf("store: %w", storage.ErrBackchannelAuthenticationNotFound)
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"not a server error", gone, false},
		{"client no longer registered", newError(ErrorUnauthorizedClient, 400, "client is no longer registered", nil), true},
		{"not found", newError(ErrorInvalidRequest, 400, "backchannel authentication handle is unknown", gone), true},
		{"plain refusal", newError(ErrorInvalidRequest, 400, "backchannel authentication handle is unknown", errors.New("store: refused")), false},
		{"outage", newError(ErrorServerError, 500, "failed to look up the backchannel authentication request", gone), false},
	} {
		if got := goneBackchannelRequest(tc.err); got != tc.want {
			t.Errorf("%s: goneBackchannelRequest = %v, want %v", tc.name, got, tc.want)
		}
	}
}

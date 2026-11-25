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

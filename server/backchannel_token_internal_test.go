package server

import (
	"errors"
	"fmt"
	"testing"

	"github.com/idfoundry/fapigo/storage"
)

// TestBackchannelPollError covers the CIBA token endpoint's answer for
// each way polling can fail (CIBA Core §11): a wrapped storage error is
// still recognized.
func TestBackchannelPollError(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want ErrorCode
	}{
		{&storage.BackchannelAuthenticationExpiredError{}, ErrorExpiredToken},
		{&storage.BackchannelAuthenticationSlowDownError{}, ErrorSlowDown},
		{fmt.Errorf("wrapped: %w", &storage.BackchannelAuthenticationSlowDownError{}), ErrorSlowDown},
		{&storage.BackchannelAuthenticationAlreadyRedeemedError{}, ErrorInvalidGrant},
		{errors.New("not found"), ErrorInvalidGrant},
	} {
		if got := backchannelPollError(tc.err); got.Code() != tc.want || got.HTTPStatus() != 400 {
			t.Errorf("backchannelPollError(%v) = %s %d, want %s 400", tc.err, got.Code(), got.HTTPStatus(), tc.want)
		}
	}
}

// TestBackchannelStatusError covers the answer for each status a polled
// request can be in: only an approved one goes on to issue tokens.
func TestBackchannelStatusError(t *testing.T) {
	for status, want := range map[storage.BackchannelAuthenticationStatus]ErrorCode{
		storage.BackchannelAuthenticationPending:              ErrorAuthorizationPending,
		storage.BackchannelAuthenticationDenied:               ErrorAccessDenied,
		storage.BackchannelAuthenticationAuthenticationFailed: ErrorAccessDenied,
		storage.BackchannelAuthenticationStatus(0):            ErrorServerError,
	} {
		if got := backchannelStatusError(status); got == nil || got.Code() != want {
			t.Errorf("backchannelStatusError(%v) = %v, want %s", status, got, want)
		}
	}
	if got := backchannelStatusError(storage.BackchannelAuthenticationApproved); got != nil {
		t.Errorf("backchannelStatusError(approved) = %v, want nil", got)
	}
}

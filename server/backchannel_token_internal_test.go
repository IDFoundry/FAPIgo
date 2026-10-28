package server

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"

	fapi "github.com/idfoundry/fapigo"
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

// TestBackchannelAuthReqIDHash covers the digest a CIBA request is
// stored under: the plain SHA-256 of an unbound auth_req_id, as before
// bindings existed, and one per client instance and dpop_jkt otherwise,
// so a poll from another instance or with another key finds nothing.
func TestBackchannelAuthReqIDHash(t *testing.T) {
	const id = "auth-req-id"
	if backchannelAuthReqIDHash(id, "", "") != sha256.Sum256([]byte(id)) {
		t.Error("an unbound auth_req_id's digest isn't its plain SHA-256")
	}
	seen := map[[32]byte]string{}
	for _, b := range [][2]string{{"", ""}, {"inst-a", ""}, {"inst-b", ""}, {"", "jkt-a"}, {"inst-a", "jkt-a"}, {"inst-a", "jkt-b"}, {"inst-aj", "kt-a"}, {"", "inst-a"}} {
		h := backchannelAuthReqIDHash(id, b[0], b[1])
		if prev, ok := seen[h]; ok {
			t.Errorf("binding %q shares a digest with %q", b, prev)
		}
		seen[h] = b[0] + "|" + b[1]
		if h != backchannelAuthReqIDHash(id, b[0], b[1]) {
			t.Errorf("binding %q isn't deterministic", b)
		}
	}
}

// TestApprovedBackchannelGrantChecksInstance: the request record's own
// client instance must match the polling instance's.
func TestApprovedBackchannelGrantChecksInstance(t *testing.T) {
	issuer, err := fapi.ParseIssuerURL("https://as.example.com")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{cfg: Config{Issuer: issuer}}
	request, err := s.encodeRequestRecord(requestRecord{ClientInstanceKey: "inst-a"})
	if err != nil {
		t.Fatalf("encodeRequestRecord: %v", err)
	}
	polled := storage.PolledBackchannelAuthentication{ClientID: "client", Request: request, Status: storage.BackchannelAuthenticationPending}
	if _, got := s.approvedBackchannelGrant(polled, "client", "", "inst-b"); got == nil || got.Code() != ErrorInvalidGrant {
		t.Errorf("another instance = %v, want invalid_grant", got)
	}
	if _, got := s.approvedBackchannelGrant(polled, "client", "", "inst-a"); got == nil || got.Code() != ErrorAuthorizationPending {
		t.Errorf("the same instance = %v, want authorization_pending", got)
	}
}

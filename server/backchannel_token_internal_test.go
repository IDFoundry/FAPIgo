package server

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/storage"
)

// TestBackchannelPollError covers the CIBA token endpoint's answer for
// each way polling can fail (CIBA Core §11): a wrapped storage error is
// still recognized, and a store that couldn't answer is the server's
// failure, not an unknown auth_req_id the client would give up on.
func TestBackchannelPollError(t *testing.T) {
	for _, tc := range []struct {
		err    error
		want   ErrorCode
		status int
	}{
		{&storage.BackchannelAuthenticationExpiredError{}, ErrorExpiredToken, 400},
		{&storage.BackchannelAuthenticationSlowDownError{}, ErrorSlowDown, 400},
		{fmt.Errorf("wrapped: %w", &storage.BackchannelAuthenticationSlowDownError{}), ErrorSlowDown, 400},
		{&storage.BackchannelAuthenticationAlreadyRedeemedError{}, ErrorInvalidGrant, 400},
		{errors.New("not found"), ErrorInvalidGrant, 400},
		{fmt.Errorf("db: %w", storage.ErrStoreUnavailable), ErrorServerError, 500},
	} {
		if got := backchannelPollError(context.Background(), tc.err); got.Code() != tc.want || got.HTTPStatus() != tc.status {
			t.Errorf("backchannelPollError(%v) = %s %d, want %s %d", tc.err, got.Code(), got.HTTPStatus(), tc.want, tc.status)
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
// stored under: one per issuer, client instance and dpop_jkt, so a
// poll to another issuer's server sharing the store, from another
// instance or with another key finds nothing, and never the plain
// SHA-256 a server before v0.84.0 stored an unbound request under.
func TestBackchannelAuthReqIDHash(t *testing.T) {
	const id = "auth-req-id"
	if backchannelAuthReqIDHash("https://as.example", id, "", "") == sha256.Sum256([]byte(id)) {
		t.Error("an unbound auth_req_id's digest is its plain SHA-256")
	}
	seen := map[[32]byte]string{}
	for _, b := range [][3]string{
		{"https://as.example", "", ""}, {"https://other.example", "", ""}, {"https://as.example", "inst-a", ""},
		{"https://as.example", "inst-b", ""}, {"https://as.example", "", "jkt-a"}, {"https://as.example", "inst-a", "jkt-a"},
		{"https://as.example", "inst-a", "jkt-b"}, {"https://as.example", "inst-aj", "kt-a"}, {"https://as.example", "", "inst-a"},
		{"https://as.exampleinst-a", "", ""}, {"", "https://as.example", ""},
	} {
		h := backchannelAuthReqIDHash(b[0], id, b[1], b[2])
		if prev, ok := seen[h]; ok {
			t.Errorf("binding %q shares a digest with %q", b, prev)
		}
		seen[h] = b[0] + "|" + b[1] + "|" + b[2]
		if h != backchannelAuthReqIDHash(b[0], id, b[1], b[2]) {
			t.Errorf("binding %q isn't deterministic", b)
		}
	}
}

// TestIsWellFormedAuthReqID: only the form generateAuthReqID gives an
// auth_req_id is well-formed. The string a bound request's digest is
// taken over never is, whatever the binding, and
// its digest as an unbound auth_req_id isn't the bound request's.
func TestIsWellFormedAuthReqID(t *testing.T) {
	id, err := generateAuthReqID(nil)
	if err != nil {
		t.Fatalf("generateAuthReqID: %v", err)
	}
	if !isWellFormedAuthReqID(id) {
		t.Fatalf("generated auth_req_id %q isn't well-formed", id)
	}
	for name, v := range map[string]string{
		"empty":         "",
		"42 characters": id[:42],
		"44 characters": id + "A",
		"NUL":           id[:42] + "\x00",
		"space":         " " + id[1:],
		"plus":          id[:42] + "+",
		"slash":         id[:42] + "/",
		"padding":       id[:42] + "=",
		"period":        id[:42] + ".",
		"non-ASCII":     id[:41] + "é",
	} {
		if isWellFormedAuthReqID(v) {
			t.Errorf("%s: %q is well-formed", name, v)
		}
	}
	const thumbprint = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"
	for name, binding := range map[string][2]string{
		"DPoP key":        {"", thumbprint},
		"client instance": {thumbprint, ""},
		"both":            {thumbprint, thumbprint},
	} {
		preimage, collides := BoundAuthReqIDPreimage("https://as.example", id, binding[0], binding[1])
		if collides {
			t.Errorf("%s: the bound digest's preimage has the bound request's digest unbound", name)
		}
		if isWellFormedAuthReqID(preimage) {
			t.Errorf("%s: the bound digest's preimage %q is well-formed", name, preimage)
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

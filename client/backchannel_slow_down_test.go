package client_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/client"
)

// TestSlowDownWidensSessionInterval: CIBA §11 — after slow_down "the
// interval MUST be increased by at least 5 seconds for this and all
// subsequent requests". The pending result carries the widened session,
// each further slow_down widens it again, authorization_pending leaves
// it as it is, and sealing keeps the widened interval.
func TestSlowDownWidensSessionInterval(t *testing.T) {
	c, as, _ := newTestClientWithCIBA(t)
	session := beginTestBackchannelSession(t, c)
	begun := session.Interval()

	as.tokenResponses = []cibaTokenResponse{
		{status: http.StatusBadRequest, body: map[string]any{"error": "slow_down"}},
		{status: http.StatusBadRequest, body: map[string]any{"error": "slow_down"}},
		{status: http.StatusBadRequest, body: map[string]any{"error": "authorization_pending"}},
	}
	for i, want := range []time.Duration{begun + 5*time.Second, begun + 10*time.Second, begun + 10*time.Second} {
		session = pollPending(t, c, session)
		if got := session.Interval(); got != want {
			t.Fatalf("poll %d: Interval() = %v, want %v", i+1, got, want)
		}
	}

	sealer, err := client.NewBackchannelSessionSealer(c, [][]byte{testSessionSealKey()})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := sealer.Seal(session, "user-1")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	opened, _, err := sealer.Open(sealed, "user-1")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if opened.Interval() != begun+10*time.Second {
		t.Errorf("opened Interval() = %v, want %v", opened.Interval(), begun+10*time.Second)
	}
}

// pollPending polls session once, requires a pending result whose
// Session is still session's auth_req_id, and returns that Session.
func pollPending(t *testing.T, c *client.Client, session client.BackchannelAuthenticationSession) client.BackchannelAuthenticationSession {
	t.Helper()
	result, err := c.PollBackchannelAuthentication(context.Background(), session)
	if err != nil {
		t.Fatalf("PollBackchannelAuthentication: %v", err)
	}
	pending, ok := result.(client.BackchannelAuthenticationPending)
	if !ok {
		t.Fatalf("result = %T, want client.BackchannelAuthenticationPending", result)
	}
	if pending.Session.AuthReqID() != session.AuthReqID() {
		t.Fatalf("pending Session auth_req_id = %q, want %q", pending.Session.AuthReqID(), session.AuthReqID())
	}
	return pending.Session
}

func testSessionSealKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}

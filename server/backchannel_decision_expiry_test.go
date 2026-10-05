package server_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// newBackchannelHarnessWithClock is a CIBA harness with a two-minute
// request lifetime, whose clock the test moves.
func newBackchannelHarnessWithClock(t *testing.T, clock *settableClock) harness {
	t.Helper()
	h := newHarnessWithBackchannelOptions(t, memstore.NewBackchannelAuthenticationStore(), func(c *server.Config) {
		c.Limits.BackchannelAuthenticationRequestLifetime = 2 * time.Minute
		c.Limits.MaxBackchannelAuthenticationRequestLifetime = 2 * time.Minute
	}, func(d *server.Dependencies) {
		d.Clock = clock
	})
	h.now = clock.Now()
	return h
}

// TestCompleteBackchannelAuthenticationRefusesDecisionAfterExpiry
// covers a decision recorded once the request's lifetime has passed:
// approvals, denials and authentication failures are all refused with
// expired_token, rather than recorded (and, for a ping client,
// notified) against a request the client can no longer redeem.
func TestCompleteBackchannelAuthenticationRefusesDecisionAfterExpiry(t *testing.T) {
	for _, tc := range []struct {
		name   string
		result func(t *testing.T, now time.Time) server.InteractionResult
	}{
		{"approve", func(t *testing.T, now time.Time) server.InteractionResult { return authorizeWithGrantID(t, now, "") }},
		{"deny", func(*testing.T, time.Time) server.InteractionResult { return server.Deny("") }},
		{"authentication failed", func(*testing.T, time.Time) server.InteractionResult { return server.AuthenticationFailed("") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			clock := &settableClock{now: start}
			h := newBackchannelHarnessWithClock(t, clock)
			required := beginBackchannel(t, h, standardBackchannelParams(t))

			clock.set(start.Add(2 * time.Minute))
			err := h.server.CompleteBackchannelAuthentication(context.Background(), server.CompleteBackchannelAuthenticationRequest{
				Handle: required.Handle, Result: tc.result(t, clock.Now()),
			})
			if serverErrorCode(t, err) != server.ErrorExpiredToken {
				t.Fatalf("decision at expiry: %v, want expired_token", err)
			}
		})
	}
}

// TestCompleteBackchannelAuthenticationAcceptsDecisionBeforeExpiry
// pins the boundary: a decision just inside the lifetime is recorded.
func TestCompleteBackchannelAuthenticationAcceptsDecisionBeforeExpiry(t *testing.T) {
	start := time.Now()
	clock := &settableClock{now: start}
	h := newBackchannelHarnessWithClock(t, clock)
	required := beginBackchannel(t, h, standardBackchannelParams(t))

	clock.set(start.Add(2*time.Minute - time.Second))
	if err := h.server.CompleteBackchannelAuthentication(context.Background(), server.CompleteBackchannelAuthenticationRequest{
		Handle: required.Handle, Result: server.Deny(""),
	}); err != nil {
		t.Fatalf("decision before expiry: %v, want nil", err)
	}
}

// legacyBackchannelStore returns stored requests without expires_at,
// as a record written before the field existed would be.
type legacyBackchannelStore struct {
	*memstore.BackchannelAuthenticationStore
}

func (s legacyBackchannelStore) LookupBackchannelAuthentication(ctx context.Context, handleHash [32]byte) (storage.LookedUpBackchannelAuthentication, error) {
	looked, err := s.BackchannelAuthenticationStore.LookupBackchannelAuthentication(ctx, handleHash)
	if err != nil {
		return looked, err
	}
	var record map[string]json.RawMessage
	if err := json.Unmarshal(looked.Request, &record); err != nil {
		return looked, err
	}
	delete(record, "expires_at")
	looked.Request, err = json.Marshal(record)
	return looked, err
}

// TestCompleteBackchannelAuthenticationAcceptsLegacyRecordWithoutExpiry
// covers a request stored before its expiry was recorded: the decision
// is judged by the store alone, as before.
func TestCompleteBackchannelAuthenticationAcceptsLegacyRecordWithoutExpiry(t *testing.T) {
	start := time.Now()
	clock := &settableClock{now: start}
	h := newHarnessWithBackchannelOptions(t, legacyBackchannelStore{memstore.NewBackchannelAuthenticationStore()}, func(c *server.Config) {
		c.Limits.BackchannelAuthenticationRequestLifetime = 2 * time.Minute
		c.Limits.MaxBackchannelAuthenticationRequestLifetime = 2 * time.Minute
	}, func(d *server.Dependencies) {
		d.Clock = clock
	})
	h.now = start
	required := beginBackchannel(t, h, standardBackchannelParams(t))

	clock.set(start.Add(3 * time.Minute))
	if err := h.server.CompleteBackchannelAuthentication(context.Background(), server.CompleteBackchannelAuthenticationRequest{
		Handle: required.Handle, Result: server.Deny(""),
	}); err != nil {
		t.Fatalf("decision on a record without expires_at: %v, want nil", err)
	}
}

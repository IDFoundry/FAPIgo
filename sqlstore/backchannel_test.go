package sqlstore_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/sqlstore"
	"github.com/idfoundry/fapigo/storage"
)

// cibaRequest is a pending CIBA request of client "c", named name, with
// a five-second poll interval.
func cibaRequest(name, mode string) storage.NewBackchannelAuthentication {
	r := storage.NewBackchannelAuthentication{
		AuthReqIDHash: sha256.Sum256([]byte("auth-req-" + name)), HandleHash: sha256.Sum256([]byte("handle-" + name)),
		ClientID: "c", Request: secretGrant, DeliveryMode: mode, PollInterval: 5 * time.Second, ExpiresAt: time.Now().Add(time.Hour),
	}
	if mode == "ping" {
		r.AuthReqID = "auth-req-" + name
		r.ClientNotificationToken = fapi.NewSecret("notify-" + name)
	}
	return r
}

// pollAt polls r's request at at, returning its error.
func pollAt(b *sqlstore.BackchannelAuthenticationStore, r storage.NewBackchannelAuthentication, at time.Time) error {
	_, err := b.PollBackchannelAuthentication(context.Background(), storage.PollBackchannelAuthentication{AuthReqIDHash: r.AuthReqIDHash, Now: at})
	return err
}

// wantSlowDown fails the test unless err is slow_down, or, with want
// false, nil.
func wantSlowDown(t *testing.T, what string, err error, want bool) {
	t.Helper()
	var slowDown *storage.BackchannelAuthenticationSlowDownError
	if got := errors.As(err, &slowDown); got != want || (!want && err != nil) {
		t.Fatalf("%s = %v, want slow_down %v", what, err, want)
	}
}

// A poll that gets slow_down is recorded too, so polling faster keeps
// getting it; a poll-mode decision leaves the interval in force, and a
// ping-mode one lifts it for the next poll only.
func TestBackchannelPollInterval(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		ctx := context.Background()
		b := freshDB(t, dialect).Backchannel()
		t0 := time.Now()
		poll, ping := cibaRequest("poll", "poll"), cibaRequest("ping", "ping")
		for _, r := range []storage.NewBackchannelAuthentication{poll, ping} {
			must(t, b.CreateBackchannelAuthentication(ctx, r))
			wantSlowDown(t, "first poll", pollAt(b, r, t0), false)
		}

		wantSlowDown(t, "poll 1s after the last", pollAt(b, poll, t0.Add(time.Second)), true)
		wantSlowDown(t, "poll 5s after the first, 4s after the slowed one", pollAt(b, poll, t0.Add(5*time.Second)), true)
		wantSlowDown(t, "poll 5s after the slowed one", pollAt(b, poll, t0.Add(10*time.Second)), false)
		_, err := b.DecideBackchannelAuthentication(ctx, storage.DecideBackchannelAuthentication{HandleHash: poll.HandleHash, Status: storage.BackchannelAuthenticationDenied})
		must(t, err)
		wantSlowDown(t, "poll-mode poll 1s after a decision", pollAt(b, poll, t0.Add(11*time.Second)), true)

		decided, err := b.DecideBackchannelAuthentication(ctx, storage.DecideBackchannelAuthentication{HandleHash: ping.HandleHash, Status: storage.BackchannelAuthenticationDenied, Reason: "no"})
		must(t, err)
		if decided.AuthReqID != "auth-req-ping" || decided.ClientNotificationToken.Reveal() != "notify-ping" || decided.DeliveryMode != "ping" {
			t.Fatalf("DecideBackchannelAuthentication(ping) = %+v", decided)
		}
		wantSlowDown(t, "ping-mode poll 1s after the decision", pollAt(b, ping, t0.Add(time.Second)), false)
		wantSlowDown(t, "the poll after that, 1s later", pollAt(b, ping, t0.Add(2*time.Second)), true)
	})
}

// A decision for an unknown handle is ErrNotFound; for a decided one,
// not. Lookup keeps answering after the decision, and an approval
// polled once is spent even after the request expires.
func TestBackchannelDecisionsAndExpiry(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		ctx := context.Background()
		b := freshDB(t, dialect).Backchannel()
		r := cibaRequest("r", "poll")
		must(t, b.CreateBackchannelAuthentication(ctx, r))
		if _, err := b.DecideBackchannelAuthentication(ctx, storage.DecideBackchannelAuthentication{HandleHash: sha256.Sum256([]byte("unknown")), Status: storage.BackchannelAuthenticationDenied}); !errors.Is(err, sqlstore.ErrNotFound) {
			t.Fatalf("DecideBackchannelAuthentication(unknown) = %v, want ErrNotFound", err)
		}
		approve := storage.DecideBackchannelAuthentication{HandleHash: r.HandleHash, Status: storage.BackchannelAuthenticationApproved, Grant: secretGrant}
		_, err := b.DecideBackchannelAuthentication(ctx, approve)
		must(t, err)
		if _, err := b.DecideBackchannelAuthentication(ctx, approve); err == nil || errors.Is(err, sqlstore.ErrNotFound) || errors.Is(err, storage.ErrStoreUnavailable) {
			t.Fatalf("second DecideBackchannelAuthentication = %v, want a refusal that isn't ErrNotFound", err)
		}
		if got, err := b.LookupBackchannelAuthentication(ctx, r.HandleHash); err != nil || got.ClientID != "c" || string(got.Request) != string(secretGrant) {
			t.Fatalf("LookupBackchannelAuthentication after the decision = %+v, %v", got, err)
		}
		must(t, pollAt(b, r, time.Now()))
		var redeemed *storage.BackchannelAuthenticationAlreadyRedeemedError
		if err := pollAt(b, r, r.ExpiresAt.Add(time.Hour)); !errors.As(err, &redeemed) {
			t.Fatalf("poll of a spent approval after expiry = %v, want already redeemed", err)
		}
	})
}

// Of concurrent decisions and polls of one approval through several
// handles — separate pools, as separate processes have — exactly one
// of each wins, and concurrent GetOrCreates for one key store one body.
func TestBackchannelAndPairwiseAtomicAcrossHandles(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		ctx := context.Background()
		p := newPlace(t, dialect)
		r := cibaRequest("r", "poll")
		must(t, p.migrated().Backchannel().CreateBackchannelAuthentication(ctx, r))
		var handles []*sqlstore.DB
		for range 4 {
			d, _ := p.openPool()
			handles = append(handles, d)
		}
		decisions := concurrentWins(handles, func(d *sqlstore.DB, _ int) bool {
			_, err := d.Backchannel().DecideBackchannelAuthentication(ctx, storage.DecideBackchannelAuthentication{HandleHash: r.HandleHash, Status: storage.BackchannelAuthenticationApproved, Grant: secretGrant})
			return err == nil
		})
		now := time.Now()
		polls := concurrentWins(handles, func(d *sqlstore.DB, _ int) bool { return pollAt(d.Backchannel(), r, now) == nil })
		if decisions != 1 || polls != 1 {
			t.Fatalf("concurrent decisions won %d times and polls %d times, want exactly 1 each", decisions, polls)
		}
		var mu sync.Mutex
		bodies := map[string]bool{}
		concurrentWins(handles, func(d *sqlstore.DB, i int) bool {
			body, err := d.PairwiseSubjects().GetOrCreate(ctx, storage.PairwiseSubjectKey{Issuer: "i", Sector: "s", Subject: "u"}, fmt.Sprint("body-", i))
			mu.Lock()
			defer mu.Unlock()
			bodies[body] = err == nil
			return err == nil
		})
		if len(bodies) != 1 {
			t.Fatalf("concurrent GetOrCreate across handles returned %v, want one body", bodies)
		}
	})
}

// concurrentWins runs fn 20 times at once, spread over handles, and
// returns how many returned true.
func concurrentWins(handles []*sqlstore.DB, fn func(d *sqlstore.DB, i int) bool) int {
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := range 20 {
		d := handles[i%len(handles)]
		wg.Go(func() {
			if fn(d, i) {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	return wins
}

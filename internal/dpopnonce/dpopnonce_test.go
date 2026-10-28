package dpopnonce

import (
	"context"
	"crypto/rand"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

const lifetime = 10 * time.Minute

func current(t *testing.T, r *Rotator, store storage.NonceStore, now time.Time) string {
	t.Helper()
	nonce, err := r.Current(context.Background(), store, rand.Reader, lifetime, now)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	return nonce
}

func checkValid(t *testing.T, store storage.NonceStore, nonce string, now time.Time, want bool) {
	t.Helper()
	valid, err := Valid(context.Background(), store, nonce, now)
	if valid != want {
		t.Fatalf("Valid(%q at %v) = %v (err %v), want %v", nonce, now, valid, err, want)
	}
}

// TestRotatorKeepsOneNonceUntilHalfItsLifetime: the same nonce is handed
// out until half its lifetime has passed, then a new one; the previous
// one stays valid until it expires, so a client holding it isn't
// challenged mid-rotation.
func TestRotatorKeepsOneNonceUntilHalfItsLifetime(t *testing.T) {
	store := memstore.NewNonceStore()
	var r Rotator
	start := time.Unix(1_800_000_000, 0)

	first := current(t, &r, store, start)
	if again := current(t, &r, store, start.Add(lifetime/2-time.Second)); again != first {
		t.Fatalf("Current before half its lifetime = %q, want the same nonce %q", again, first)
	}
	second := current(t, &r, store, start.Add(lifetime/2))
	if second == first || second == "" {
		t.Fatalf("Current at half its lifetime = %q, want a new nonce", second)
	}

	checkValid(t, store, first, start.Add(lifetime), true)
	checkValid(t, store, first, start.Add(lifetime+time.Second), false)
	checkValid(t, store, second, start.Add(lifetime+time.Second), true)
}

// TestValidRepeatedly: Valid never retires a nonce, so concurrent
// checks of one nonce all succeed.
func TestValidRepeatedly(t *testing.T) {
	store := memstore.NewNonceStore()
	var r Rotator
	now := time.Unix(1_800_000_000, 0)
	nonce := current(t, &r, store, now)

	var wg sync.WaitGroup
	results := make(chan bool, 32)
	for range 32 {
		wg.Go(func() {
			valid, _ := Valid(context.Background(), store, nonce, now)
			results <- valid
		})
	}
	wg.Wait()
	close(results)
	for valid := range results {
		if !valid {
			t.Fatal("a concurrent Valid of a current nonce returned false")
		}
	}
}

func TestValidRejectsMissingAndUnknownNonces(t *testing.T) {
	store := memstore.NewNonceStore()
	now := time.Unix(1_800_000_000, 0)
	checkValid(t, store, "", now, false)
	if valid, err := Valid(context.Background(), store, "never-issued", now); valid || err == nil {
		t.Fatalf("Valid(unknown) = %v, %v; want false and the store's error", valid, err)
	}
}

type failingStore struct{}

func (failingStore) Issue(context.Context, storage.NonceIssuance) error {
	return errors.New("down")
}

func (failingStore) Lookup(context.Context, storage.NonceLookup) (storage.NonceRecord, error) {
	return storage.NonceRecord{}, errors.New("down")
}

// TestRotatorRetriesAfterAFailedIssue: a store that couldn't persist a
// nonce leaves the Rotator without one, so the next call tries again
// rather than handing out a nonce no verifier would accept.
func TestRotatorRetriesAfterAFailedIssue(t *testing.T) {
	var r Rotator
	now := time.Unix(1_800_000_000, 0)
	if _, err := r.Current(context.Background(), failingStore{}, rand.Reader, lifetime, now); err == nil {
		t.Fatal("Current over a failing store = nil error, want error")
	}
	if nonce := current(t, &r, memstore.NewNonceStore(), now); nonce == "" {
		t.Fatal("Current after a failed Issue = \"\", want a new nonce")
	}
}

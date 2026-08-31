package main

import (
	"testing"
	"time"
)

type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time { return c.now }

func TestPendingSetPutThenTakeOnce(t *testing.T) {
	clock := &fakeClock{now: time.Now()}
	s := newPendingSet[string, string](clock)

	s.Put("key-1", "value-1", time.Minute)

	got, ok := s.TakeOnce("key-1")
	if !ok || got != "value-1" {
		t.Fatalf("TakeOnce = (%q, %v), want (%q, true)", got, ok, "value-1")
	}
}

func TestPendingSetTakeOnceIsSingleUse(t *testing.T) {
	clock := &fakeClock{now: time.Now()}
	s := newPendingSet[string, string](clock)
	s.Put("key-1", "value-1", time.Minute)

	if _, ok := s.TakeOnce("key-1"); !ok {
		t.Fatalf("first TakeOnce = false, want true")
	}
	if _, ok := s.TakeOnce("key-1"); ok {
		t.Fatalf("second TakeOnce = true, want false (single-use)")
	}
}

func TestPendingSetTakeOnceUnknownKeyMisses(t *testing.T) {
	clock := &fakeClock{now: time.Now()}
	s := newPendingSet[string, string](clock)

	if _, ok := s.TakeOnce("never-put"); ok {
		t.Fatalf("TakeOnce(unknown key) = true, want false")
	}
}

func TestPendingSetTakeOnceMissesAfterTTLExpires(t *testing.T) {
	clock := &fakeClock{now: time.Now()}
	s := newPendingSet[string, string](clock)
	s.Put("key-1", "value-1", time.Minute)

	clock.now = clock.now.Add(2 * time.Minute)

	if _, ok := s.TakeOnce("key-1"); ok {
		t.Fatalf("TakeOnce(expired entry) = true, want false")
	}
}

// TestPendingSetPutSweepsExpiredEntries confirms an abandoned entry —
// one Put but never TakeOnce'd — doesn't survive forever: a later Put,
// once its own TTL has passed, sweeps it out of the underlying map.
func TestPendingSetPutSweepsExpiredEntries(t *testing.T) {
	clock := &fakeClock{now: time.Now()}
	s := newPendingSet[string, string](clock)
	s.Put("abandoned", "value-1", time.Minute)

	clock.now = clock.now.Add(2 * time.Minute)
	s.Put("key-2", "value-2", time.Minute)

	if len(s.items) != 1 {
		t.Fatalf("len(items) = %d, want 1 (abandoned entry should have been swept)", len(s.items))
	}
	if _, ok := s.items["abandoned"]; ok {
		t.Fatalf("abandoned entry survived past its own TTL")
	}
}

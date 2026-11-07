package sqlstore

import (
	"crypto/sha256"
	"testing"
	"time"
)

// A read that started before a write to its client stores nothing,
// so with a TTL it can't serve what the write replaced; one that
// started after it does.
func TestClientCacheStoreAfterInvalidate(t *testing.T) {
	c := &clientCache{ttl: time.Hour}
	sum := sha256.Sum256([]byte("old"))
	read := c.begin()
	c.invalidate("c") // a Put, committed while the read ran
	c.store("c", sum, parsedClient, "old", read)
	if _, ok := c.fresh("c", parsedClient); ok {
		t.Fatal("a read from before an invalidation was stored")
	}
	if _, ok := c.lookup("c", sum, parsedClient, c.begin()); ok {
		t.Fatal("a read from before an invalidation was stored")
	}
	read = c.begin()
	c.store("c", sha256.Sum256([]byte("new")), parsedClient, "new", read)
	if v, ok := c.fresh("c", parsedClient); !ok || v != "new" {
		t.Fatalf("fresh = %v, %v, want the read from after the invalidation", v, ok)
	}
}

// A read that began before another, and stores late, doesn't replace
// the configuration the later read stored: the row may have changed
// between their SELECTs. Each entry's ttl runs from when the read that
// returned it began, however late it stored it, and a late read of the
// same configuration doesn't wind it back.
func TestClientCacheLateReadKeepsNewerEntry(t *testing.T) {
	now := time.Unix(1000, 0)
	c := &clientCache{ttl: 10 * time.Second, now: func() time.Time { return now }}
	oldSum, newSum := sha256.Sum256([]byte("old")), sha256.Sum256([]byte("new"))

	stalled := c.begin() // reads "old", then stalls
	now = now.Add(time.Second)
	later := c.begin() // reads "new", after another DB changed the row
	c.store("c", newSum, parsedClient, "new", later)
	now = now.Add(5 * time.Second)
	c.store("c", oldSum, parsedClient, "old", stalled)
	if v, ok := c.fresh("c", parsedClient); !ok || v != "new" {
		t.Fatalf("fresh = %v, %v, want the later read's configuration", v, ok)
	}
	if _, ok := c.lookup("c", oldSum, parsedClient, stalled); ok {
		t.Fatal("the stalled read's configuration was stored")
	}
	c.store("c", newSum, parsedKeys, "new keys", stalled) // the same configuration: kept, its ttl unchanged
	if v, ok := c.fresh("c", parsedKeys); !ok || v != "new keys" {
		t.Fatalf("fresh keys = %v, %v, want the stalled read's parse of the same configuration", v, ok)
	}

	now = time.Unix(1000, 0).Add(10*time.Second + 500*time.Millisecond)
	if _, ok := c.fresh("c", parsedKeys); !ok {
		t.Fatal("the stalled read wound the entry's ttl back to when it began")
	}
	now = time.Unix(1000, 0).Add(time.Second + 10*time.Second) // ttl after the later read began
	if _, ok := c.fresh("c", parsedClient); ok {
		t.Fatal("the entry outlived the ttl from when its read began")
	}

	slow := c.begin()
	now = now.Add(9 * time.Second)
	c.store("d", oldSum, parsedClient, "slow", slow) // stored 9 s after its read began
	now = now.Add(time.Second)
	if _, ok := c.fresh("d", parsedClient); ok {
		t.Fatal("a slow read's ttl ran from when it stored, not when it began")
	}

	// A later read replaces an entry for another configuration read earlier.
	c.store("d", newSum, parsedClient, "newer", c.begin())
	if v, ok := c.fresh("d", parsedClient); !ok || v != "newer" {
		t.Fatalf("fresh = %v, %v, want the newer read's configuration", v, ok)
	}
}

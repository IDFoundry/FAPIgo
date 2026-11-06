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
	gen := c.generation()
	c.invalidate("c") // a Put, committed while the read ran
	c.store("c", sum, parsedClient, "old", gen)
	if _, ok := c.fresh("c", parsedClient); ok {
		t.Fatal("a read from before an invalidation was stored")
	}
	if _, ok := c.lookup("c", sum, parsedClient); ok {
		t.Fatal("a read from before an invalidation was stored")
	}
	gen = c.generation()
	c.store("c", sha256.Sum256([]byte("new")), parsedClient, "new", gen)
	if v, ok := c.fresh("c", parsedClient); !ok || v != "new" {
		t.Fatalf("fresh = %v, %v, want the read from after the invalidation", v, ok)
	}
}

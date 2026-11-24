package client

import (
	"context"
	"strconv"
	"testing"
)

// TestInMemoryDPoPNonceCacheIsBounded: the cache holds at most
// maxCachedDPoPNonceScopes scopes. A new scope past the bound replaces
// another, the one just set is always kept, and replacing a cached
// scope's nonce evicts nothing.
func TestInMemoryDPoPNonceCacheIsBounded(t *testing.T) {
	ctx := context.Background()
	c := NewInMemoryDPoPNonceCache()
	for i := range maxCachedDPoPNonceScopes {
		c.Set(ctx, "https://rs"+strconv.Itoa(i)+".example", "n")
	}
	if len(c.nonces) != maxCachedDPoPNonceScopes {
		t.Fatalf("cached %d scopes, want %d", len(c.nonces), maxCachedDPoPNonceScopes)
	}
	c.Set(ctx, "https://rs0.example", "fresh")
	if len(c.nonces) != maxCachedDPoPNonceScopes {
		t.Fatalf("replacing a cached scope's nonce left %d scopes, want %d", len(c.nonces), maxCachedDPoPNonceScopes)
	}
	if got, _ := c.Get(ctx, "https://rs0.example"); got != "fresh" {
		t.Fatalf("Get(rs0) = %q, want the replaced nonce", got)
	}
	for i := range 10 {
		scope := "https://new" + strconv.Itoa(i) + ".example"
		c.Set(ctx, scope, "m")
		if got, ok := c.Get(ctx, scope); !ok || got != "m" {
			t.Fatalf("Get(%s) = %q, %v; want the nonce just set", scope, got, ok)
		}
		if len(c.nonces) != maxCachedDPoPNonceScopes {
			t.Fatalf("cached %d scopes after a new one, want %d", len(c.nonces), maxCachedDPoPNonceScopes)
		}
	}
}

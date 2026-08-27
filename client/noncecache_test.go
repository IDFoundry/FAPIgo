package client_test

import (
	"context"
	"sync"
	"testing"

	"github.com/idfoundry/fapigo/client"
)

func TestInMemoryDPoPNonceCacheRoundTrips(t *testing.T) {
	c := client.NewInMemoryDPoPNonceCache()
	ctx := context.Background()

	if _, ok := c.Get(ctx, "as"); ok {
		t.Fatalf("Get(unset scope) ok = true, want false")
	}

	c.Set(ctx, "as", "nonce-1")
	got, ok := c.Get(ctx, "as")
	if !ok || got != "nonce-1" {
		t.Fatalf("Get(as) = (%q, %v), want (%q, true)", got, ok, "nonce-1")
	}

	c.Set(ctx, "as", "nonce-2")
	got, ok = c.Get(ctx, "as")
	if !ok || got != "nonce-2" {
		t.Fatalf("Get(as) after overwrite = (%q, %v), want (%q, true)", got, ok, "nonce-2")
	}
}

func TestInMemoryDPoPNonceCacheIsolatesScopes(t *testing.T) {
	c := client.NewInMemoryDPoPNonceCache()
	ctx := context.Background()

	c.Set(ctx, "as", "as-nonce")
	c.Set(ctx, "https://rs.example.com", "rs-nonce")

	if got, ok := c.Get(ctx, "as"); !ok || got != "as-nonce" {
		t.Fatalf("Get(as) = (%q, %v), want (%q, true)", got, ok, "as-nonce")
	}
	if got, ok := c.Get(ctx, "https://rs.example.com"); !ok || got != "rs-nonce" {
		t.Fatalf("Get(rs) = (%q, %v), want (%q, true)", got, ok, "rs-nonce")
	}
	if _, ok := c.Get(ctx, "https://other.example.com"); ok {
		t.Fatalf("Get(never-set scope) ok = true, want false")
	}
}

func TestInMemoryDPoPNonceCacheConcurrentUse(t *testing.T) {
	c := client.NewInMemoryDPoPNonceCache()
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			c.Set(ctx, "as", "nonce")
		}()
		go func() {
			defer wg.Done()
			c.Get(ctx, "as")
		}()
	}
	wg.Wait()
}

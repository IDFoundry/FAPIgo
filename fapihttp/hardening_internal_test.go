package fapihttp

import (
	"net/http"
	"runtime"
	"testing"
	"time"
	"weak"
)

// TestHardenedRegistryDoesNotKeepTransportsAlive: recording a transport
// doesn't keep it alive, and its entry goes once it's collected.
func TestHardenedRegistryDoesNotKeepTransportsAlive(t *testing.T) {
	c, err := NewClient(RecommendedTransportConfig())
	if err != nil {
		t.Fatal(err)
	}
	key := weak.Make(c.Transport.(*http.Transport))
	if _, ok := hardenedTransports.Load(key); !ok {
		t.Fatal("NewClient's transport isn't recorded")
	}
	c = nil //nolint:ineffassign,wastedassign // drop the only strong reference
	deadline := time.Now().Add(5 * time.Second)
	for {
		runtime.GC()
		if _, ok := hardenedTransports.Load(key); !ok && key.Value() == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the transport's record outlived it")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

package client_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/storage"
)

// TestProtectedResourceDoLeavesTheCallersRequestUntouched: Do sends its
// own copy, so the caller's request never carries the access token or
// a DPoP proof afterwards, under either sender constraint.
func TestProtectedResourceDoLeavesTheCallersRequestUntouched(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	for name, mutate := range map[string]func(*client.Config){
		"dpop": nil,
		"mtls": func(cfg *client.Config) {
			cfg.SenderConstrain = storage.SenderConstrainMTLS
			cfg.Algorithms.DPoP = 0
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := newResourceTestClient(t, ts, mutate)
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/resource", nil)
			if err != nil {
				t.Fatalf("NewRequestWithContext: %v", err)
			}
			res, err := c.ProtectedResource(client.TokenSet{AccessToken: fapi.NewSecret("secret-access-token")}).Do(context.Background(), req)
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			_ = res.Body.Close()
			if got := req.Header.Get("Authorization"); got != "" {
				t.Errorf("caller's request Authorization = %q after Do, want none", got)
			}
			if got := req.Header.Get("DPoP"); got != "" {
				t.Errorf("caller's request DPoP = %q after Do, want none", got)
			}
		})
	}
}

// TestProtectedResourceDoSharedRequestTemplate: one request reused as a
// template from many goroutines, each with its own user's token, sends
// each request with that goroutine's token (run with -race).
func TestProtectedResourceDoSharedRequestTemplate(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]int{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.Header.Get("Authorization")+"|"+r.URL.Query().Get("want")]++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	c := newResourceTestClient(t, ts, func(cfg *client.Config) {
		cfg.SenderConstrain = storage.SenderConstrainMTLS
		cfg.Algorithms.DPoP = 0
	})
	template, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/resource", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	const users = 16
	var wg sync.WaitGroup
	for i := range users {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token := fmt.Sprintf("token-of-user-%d", i)
			req := template.WithContext(context.Background())
			res, err := c.ProtectedResource(client.TokenSet{AccessToken: fapi.NewSecret(token)}).Do(context.Background(), req)
			if err != nil {
				t.Errorf("Do(user %d): %v", i, err)
				return
			}
			_ = res.Body.Close()
		}()
	}
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	for i := range users {
		key := fmt.Sprintf("Bearer token-of-user-%d|", i)
		if seen[key] != 1 {
			t.Errorf("user %d's token was sent %d times, want 1 (seen %v)", i, seen[key], seen)
		}
	}
	if got := template.Header.Get("Authorization"); got != "" {
		t.Errorf("template Authorization = %q after Do, want none", got)
	}
}

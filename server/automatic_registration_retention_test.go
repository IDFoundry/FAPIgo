package server_test

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"unsafe"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/server"
)

// discardingAuditSink records nothing, so a test measuring what a
// server keeps in memory doesn't count its own audit log.
type discardingAuditSink struct{}

func (discardingAuditSink) Record(context.Context, server.AuditEvent) error { return nil }

// TestUnresolvableFederationClientIDsDontKeepTheirRequests: pushed
// authorization requests whose client_id, an Entity Identifier no Trust
// Chain resolves, is a substring of a 64 KiB form (as a client_id an
// adapter slices out of the body it read would be) are refused
// invalid_client, with the failure remembered for each, and leave
// neither the forms nor anything sharing their memory alive: the
// client_ids the failure cache keeps, and whatever it hands the
// operator's OnResolutionFailure hook, are copies. federation's own
// tests check the caches' keys directly; this checks the whole path
// from the server down.
func TestUnresolvableFederationClientIDsDontKeepTheirRequests(t *testing.T) {
	f := setupAutomaticRegistrationFixture(t, testRedirectURI)
	var failures atomic.Int64
	var hookShared atomic.Bool
	var current atomic.Pointer[string]
	srv := newAutomaticRegistrationTestServer(t, f, func(cfg *server.Config, deps *server.Dependencies) {
		cfg.AutomaticRegistration.OnResolutionFailure = func(_ context.Context, id fapi.ClientID, _ error) {
			failures.Add(1)
			if body := current.Load(); body != nil && sharesMemory(string(id), *body) {
				hookShared.Store(true)
			}
		}
		deps.Audit = discardingAuditSink{}
	})

	const requests, padding = 200, 64 << 10
	push := func(i int) {
		const name = "client_id="
		id := fmt.Sprintf("%s/unresolvable-%04d", f.rpID, i)
		body := name + id + "&padding=" + strings.Repeat("p", padding)
		current.Store(&body)
		_, err := srv.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
			HTTP: server.FormRequest{Parameters: []server.FormParameter{{Name: "client_id", Value: body[len(name) : len(name)+len(id)]}}},
		})
		if code := serverErrorCode(t, err); code != server.ErrorInvalidClient {
			t.Fatalf("request %d: error code %q, want %q", i, code, server.ErrorInvalidClient)
		}
	}
	push(requests) // the fetcher's connections, before measuring
	current.Store(nil)
	before := liveHeap()
	for i := range requests {
		push(i)
	}
	current.Store(nil)
	retained := liveHeap() - before
	runtime.KeepAlive(srv)

	if got := failures.Load(); got != requests+1 {
		t.Fatalf("OnResolutionFailure heard %d failures, want %d: the requests didn't all reach a resolution", got, requests+1)
	}
	if hookShared.Load() {
		t.Error("OnResolutionFailure was handed a client_id sharing the request's memory")
	}
	// Kept, the forms would take 12.5 MiB.
	if retained > 2<<20 {
		t.Fatalf("%d refused requests of %d bytes each left %d bytes more in use, want at most 2 MiB", requests, padding, retained)
	}
}

// sharesMemory reports whether s lies within within's bytes.
func sharesMemory(s, within string) bool {
	if s == "" || within == "" {
		return false
	}
	start := uintptr(unsafe.Pointer(unsafe.StringData(within)))
	p := uintptr(unsafe.Pointer(unsafe.StringData(s)))
	return p >= start && p < start+uintptr(len(within))
}

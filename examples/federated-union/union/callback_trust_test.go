package union_test

import (
	"net/http"
	"net/url"
	"testing"
)

// TestCallbackRechecksTrust covers the service resolving the provider
// again at the callback, rather than reusing a client cached at login:
// Eastmark suspended from the Union between the citizen's login and
// their return is refused there, and no claims are shared.
func TestCallbackRechecksTrust(t *testing.T) {
	w, n := startUnion(t)
	b := newBrowser(t, n)
	startConsent(t, w, b, "bank.southport.localhost", "id.eastmark.localhost")

	w.Scenes().SuspendEastmark.Store(true)
	status, body, at := b.post(w.URL("id.eastmark.localhost", "/authorize"), url.Values{
		"citizen": {"em-3306"}, "decision": {"approve"}, "claim": {"given_name"},
	})
	if at.Hostname() != "bank.southport.localhost" || status != http.StatusForbidden {
		t.Fatalf("callback after suspension = %d at %s, want 403 at the bank:\n%s", status, at, body)
	}
	mustContain(t, body, "is not trusted")
}

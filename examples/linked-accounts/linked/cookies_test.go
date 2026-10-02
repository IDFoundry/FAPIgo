package linked_test

import (
	"net/url"
	"testing"
)

// TestCallbackClearsTheSessionCookie covers the client session cookie
// being expired once the callback has used it: the session is
// single-use, so the browser shouldn't keep presenting it.
func TestCallbackClearsTheSessionCookie(t *testing.T) {
	d := start(t)
	d.linkAccounts(everyday)
	u, err := url.Parse(d.world.URL("pocketwise.localhost", "/"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range d.http.Jar.Cookies(u) {
		if c.Name == "pocketwise_session" {
			t.Errorf("the browser still holds %s after the callback", c.Name)
		}
	}
}

package payment_test

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// TestMalformedRequestGetsNoInternalDetail covers what the bank sends a
// client whose request it can't read: invalid_request with a fixed
// description, not the parser's own error text.
func TestMalformedRequestGetsNoInternalDetail(t *testing.T) {
	d := start(t)
	res, err := d.http.Post(d.world.URL("bank.localhost", "/par"), "text/plain", strings.NewReader("not a form"))
	if err != nil {
		t.Fatalf("POST /par: %v", err)
	}
	defer func() { _ = res.Body.Close() }()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), `"invalid_request"`) {
		t.Fatalf("POST /par (text/plain) = %d %s, want 400 invalid_request", res.StatusCode, body)
	}
	if strings.Contains(string(body), "content type") || strings.Contains(string(body), "server:") {
		t.Errorf("response carries internal detail: %s", body)
	}
}

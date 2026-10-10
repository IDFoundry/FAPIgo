package server

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestErrorWriteTextOmitsCause covers WriteText, the helper for
// LocalErrorResponse and AuthorizationLocalError: the status, code and
// public description reach the browser, and a wrapped internal cause
// (which Error() includes) never does.
func TestErrorWriteTextOmitsCause(t *testing.T) {
	err := newError(ErrorInvalidRequest, 400, "request_uri is expired", errors.New("store: connection refused to 10.0.0.7"))
	if !strings.Contains(err.Error(), "10.0.0.7") {
		t.Fatalf("Error() = %q, want it to carry the cause", err.Error())
	}

	rec := httptest.NewRecorder()
	err.WriteText(rec)

	if rec.Code != 400 {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if body := strings.TrimSpace(rec.Body.String()); body != "invalid_request: request_uri is expired" {
		t.Fatalf("body = %q", body)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", cc)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("Content-Type = %q, want text/plain", ct)
	}
}

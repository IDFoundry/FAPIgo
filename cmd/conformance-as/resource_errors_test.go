package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	fapires "github.com/idfoundry/fapigo/resource"
)

// TestWriteResourceErrors: a 500 that isn't about the request's
// credentials carries no challenge, and a resource error carries the
// resource package's own.
func TestWriteResourceErrors(t *testing.T) {
	rec := httptest.NewRecorder()
	writeServerError(rec, "failed to sign userinfo response")
	if rec.Code != http.StatusInternalServerError || rec.Header().Get("WWW-Authenticate") != "" ||
		!strings.Contains(rec.Body.String(), `"server_error"`) {
		t.Errorf("writeServerError = %d %q %s, want a 500 server_error with no challenge",
			rec.Code, rec.Header().Get("WWW-Authenticate"), rec.Body)
	}

	rec = httptest.NewRecorder()
	writeResourceError(rec, fapires.NewError(fapires.ErrorInvalidToken, http.StatusUnauthorized, "expired"))
	if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") != `Bearer error="invalid_token"` {
		t.Errorf("writeResourceError = %d %q, want 401 with a Bearer invalid_token challenge",
			rec.Code, rec.Header().Get("WWW-Authenticate"))
	}

	rec = httptest.NewRecorder()
	writeResourceError(rec, errors.New("directory unavailable"))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("writeResourceError(plain error) = %d, want 500", rec.Code)
	}
}

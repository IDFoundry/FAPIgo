package resource_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/idfoundry/fapigo/resource"
)

// TestNewErrorWriteJSON covers the public encoding path an HTTP
// adapter uses for a failure it detected itself, before ever calling
// Verify (resource.NewError), and the RFC 6750 §3.1 wire format
// WriteJSON produces for it — WWW-Authenticate, Content-Type, status
// code, and the {"error", "error_description"} body.
func TestNewErrorWriteJSON(t *testing.T) {
	err := resource.NewError(resource.ErrorInvalidToken, 401, "token has expired")

	rec := httptest.NewRecorder()
	err.WriteJSON(rec)

	if rec.Code != 401 {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want %q", ct, "application/json")
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != `Bearer error="invalid_token"` {
		t.Fatalf("WWW-Authenticate = %q, want %q", got, `Bearer error="invalid_token"`)
	}
	if rec.Header().Get("DPoP-Nonce") != "" {
		t.Fatalf("DPoP-Nonce header = %q, want none for a NewError-built error", rec.Header().Get("DPoP-Nonce"))
	}
	var body struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if decodeErr := json.Unmarshal(rec.Body.Bytes(), &body); decodeErr != nil {
		t.Fatalf("unmarshal body: %v (body: %s)", decodeErr, rec.Body.Bytes())
	}
	if body.Error != string(resource.ErrorInvalidToken) {
		t.Fatalf("error = %q, want %q", body.Error, resource.ErrorInvalidToken)
	}
	if body.ErrorDescription != "token has expired" {
		t.Fatalf("error_description = %q, want %q", body.ErrorDescription, "token has expired")
	}
}

// TestErrorWriteJSONUsesDPoPSchemeForUseDPoPNonce covers WriteJSON's
// scheme selection — see its own doc comment for why ErrorUseDPoPNonce
// is the one code that always challenges with "DPoP", not "Bearer".
func TestErrorWriteJSONUsesDPoPSchemeForUseDPoPNonce(t *testing.T) {
	err := resource.NewError(resource.ErrorUseDPoPNonce, 401, "nonce required")

	rec := httptest.NewRecorder()
	err.WriteJSON(rec)

	if got := rec.Header().Get("WWW-Authenticate"); got != `DPoP error="use_dpop_nonce"` {
		t.Fatalf("WWW-Authenticate = %q, want %q", got, `DPoP error="use_dpop_nonce"`)
	}
}

// TestErrorWriteJSONOmitsEmptyDescription covers WriteJSON's own
// omitempty behavior for error_description.
func TestErrorWriteJSONOmitsEmptyDescription(t *testing.T) {
	err := resource.NewError(resource.ErrorInvalidRequest, 400, "")

	rec := httptest.NewRecorder()
	err.WriteJSON(rec)

	var raw map[string]json.RawMessage
	if decodeErr := json.Unmarshal(rec.Body.Bytes(), &raw); decodeErr != nil {
		t.Fatalf("unmarshal body: %v (body: %s)", decodeErr, rec.Body.Bytes())
	}
	if _, ok := raw["error_description"]; ok {
		t.Fatalf("body = %s, want no error_description member for an empty description", rec.Body.Bytes())
	}
}

// TestWriteErrorWithResourceError covers WriteError's main path: a
// *resource.Error (wrapped, since errors.As must unwrap it, not just
// type-assert) is encoded via its own WriteJSON.
func TestWriteErrorWithResourceError(t *testing.T) {
	err := resource.NewError(resource.ErrorInvalidToken, 401, "token has expired")
	wrapped := fmt.Errorf("verify failed: %w", err)

	rec := httptest.NewRecorder()
	resource.WriteError(rec, wrapped)

	if rec.Code != 401 {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	var body struct {
		Error string `json:"error"`
	}
	if decodeErr := json.Unmarshal(rec.Body.Bytes(), &body); decodeErr != nil {
		t.Fatalf("unmarshal body: %v (body: %s)", decodeErr, rec.Body.Bytes())
	}
	if body.Error != string(resource.ErrorInvalidToken) {
		t.Fatalf("error = %q, want %q", body.Error, resource.ErrorInvalidToken)
	}
}

// TestWriteErrorFallsBackForUnknownError covers WriteError's other
// branch: an error that isn't (and doesn't wrap) a *resource.Error gets
// a generic 500.
func TestWriteErrorFallsBackForUnknownError(t *testing.T) {
	rec := httptest.NewRecorder()
	resource.WriteError(rec, errors.New("something unrelated failed"))

	if rec.Code != 500 {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

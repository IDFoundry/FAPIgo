package server_test

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/idfoundry/fapigo/server"
)

// TestNewErrorWriteJSON covers the public encoding path an HTTP
// adapter uses for a failure it detected itself, before ever calling a
// Server method (server.NewError), and the RFC 6749 §5.2 wire format
// WriteJSON produces for it — Content-Type, status code, and the
// {"error", "error_description"} body.
func TestNewErrorWriteJSON(t *testing.T) {
	err := server.NewError(server.ErrorUnsupportedGrantType, 400, "grant_type must be authorization_code")

	rec := httptest.NewRecorder()
	err.WriteJSON(rec)

	if rec.Code != 400 {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want %q", ct, "application/json")
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
	if body.Error != string(server.ErrorUnsupportedGrantType) {
		t.Fatalf("error = %q, want %q", body.Error, server.ErrorUnsupportedGrantType)
	}
	if body.ErrorDescription != "grant_type must be authorization_code" {
		t.Fatalf("error_description = %q, want %q", body.ErrorDescription, "grant_type must be authorization_code")
	}
}

// TestErrorWriteJSONOmitsEmptyDescription covers WriteJSON's own
// omitempty behavior for error_description — RFC 6749 §5.2 marks it
// optional, and a response that includes it as an empty string is a
// different (and less correct) wire shape than omitting the member
// entirely.
func TestErrorWriteJSONOmitsEmptyDescription(t *testing.T) {
	err := server.NewError(server.ErrorInvalidRequest, 400, "")

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

// TestErrorWriteJSONIncludesDPoPNonceHeader covers WriteJSON's other
// branch: a real *server.Error carrying a Nonce (RFC 9449 §8, only ever
// produced by this package's own DPoP-nonce-challenge machinery, not
// constructible via NewError) must have that nonce set as the
// response's own DPoP-Nonce header.
func TestErrorWriteJSONIncludesDPoPNonceHeader(t *testing.T) {
	h, _ := newHarnessWithNonces(t)
	dpopKey := generateKey(t)

	_, err := exchangeWithDPoPNonce(t, h, dpopKey, "")
	if err == nil {
		t.Fatalf("ExchangeAuthorizationCode(no nonce) = nil error, want error")
	}
	serr, ok := err.(*server.Error)
	if !ok {
		t.Fatalf("error type = %T, want *server.Error", err)
	}
	if serr.Nonce() == "" {
		t.Fatalf("Nonce() is empty, want a freshly issued nonce")
	}

	rec := httptest.NewRecorder()
	serr.WriteJSON(rec)

	if got := rec.Header().Get("DPoP-Nonce"); got != serr.Nonce() {
		t.Fatalf("DPoP-Nonce header = %q, want %q", got, serr.Nonce())
	}
	if rec.Code != serr.HTTPStatus() {
		t.Fatalf("status = %d, want %d", rec.Code, serr.HTTPStatus())
	}
}

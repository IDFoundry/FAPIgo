package server_test

import (
	"net/http/httptest"
	"testing"

	"github.com/idfoundry/fapigo/server"
)

// TestNewErrorNormalizesInvalidInput: a code outside RFC 6749 §5.2's
// character set (or empty), or a status that isn't 4xx/5xx, becomes a
// 500 server_error, so it can't produce a malformed response or panic
// when written; a description outside the character set is dropped.
func TestNewErrorNormalizesInvalidInput(t *testing.T) {
	for _, tc := range []struct {
		name            string
		code            server.ErrorCode
		status          int
		description     string
		wantCode        server.ErrorCode
		wantStatus      int
		wantDescription string
	}{
		{"valid", server.ErrorUnsupportedGrantType, 400, "grant_type is unsupported", server.ErrorUnsupportedGrantType, 400, "grant_type is unsupported"},
		{"empty code", "", 400, "x", server.ErrorServerError, 500, "x"},
		{"code with a quote", `invalid_request"`, 400, "", server.ErrorServerError, 500, ""},
		{"code with a newline", "invalid_request\n", 400, "", server.ErrorServerError, 500, ""},
		{"status zero", server.ErrorInvalidRequest, 0, "", server.ErrorServerError, 500, ""},
		{"success status", server.ErrorInvalidRequest, 302, "", server.ErrorServerError, 500, ""},
		{"description outside the character set", server.ErrorInvalidRequest, 400, "bad\\path", server.ErrorInvalidRequest, 400, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := server.NewError(tc.code, tc.status, tc.description)
			if e.Code() != tc.wantCode || e.HTTPStatus() != tc.wantStatus || e.PublicDescription() != tc.wantDescription {
				t.Fatalf("NewError = %q/%d/%q, want %q/%d/%q", e.Code(), e.HTTPStatus(), e.PublicDescription(), tc.wantCode, tc.wantStatus, tc.wantDescription)
			}
			rec := httptest.NewRecorder()
			e.WriteJSON(rec)
			if rec.Code != tc.wantStatus {
				t.Errorf("written status = %d, want %d", rec.Code, tc.wantStatus)
			}
		})
	}
}

// TestZeroErrorWriteJSONDoesNotPanic: an *Error that never went
// through a constructor writes a 500 rather than panicking in
// WriteHeader.
func TestZeroErrorWriteJSONDoesNotPanic(t *testing.T) {
	rec := httptest.NewRecorder()
	new(server.Error).WriteJSON(rec)
	if rec.Code != 500 {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}

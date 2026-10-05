package httperror_test

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/idfoundry/fapigo/internal/httperror"
)

func TestMessageWithoutCause(t *testing.T) {
	got := httperror.Message("server", "invalid_request", "missing client_id", nil)
	want := "server: invalid_request: missing client_id"
	if got != want {
		t.Fatalf("Message() = %q, want %q", got, want)
	}
}

func TestMessageWithCause(t *testing.T) {
	cause := errors.New("boom")
	got := httperror.Message("resource", "invalid_token", "expired", cause)
	want := "resource: invalid_token: expired: boom"
	if got != want {
		t.Fatalf("Message() = %q, want %q", got, want)
	}
}

func TestWriteJSONPlain(t *testing.T) {
	rec := httptest.NewRecorder()
	httperror.WriteJSON(rec, "", "", "not_found", "no such subordinate", 404)

	if rec.Code != 404 {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	if rec.Header().Get("DPoP-Nonce") != "" {
		t.Fatalf("DPoP-Nonce = %q, want none", rec.Header().Get("DPoP-Nonce"))
	}
	if rec.Header().Get("WWW-Authenticate") != "" {
		t.Fatalf("WWW-Authenticate = %q, want none", rec.Header().Get("WWW-Authenticate"))
	}
	var body struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if body.Error != "not_found" || body.ErrorDescription != "no such subordinate" {
		t.Fatalf("body = %+v, want error=not_found, error_description=\"no such subordinate\"", body)
	}
}

func TestWriteJSONWithNonceAndChallengeScheme(t *testing.T) {
	rec := httptest.NewRecorder()
	httperror.WriteJSON(rec, "fresh-nonce", "DPoP", "use_dpop_nonce", "nonce required", 401)

	if got := rec.Header().Get("DPoP-Nonce"); got != "fresh-nonce" {
		t.Fatalf("DPoP-Nonce = %q, want %q", got, "fresh-nonce")
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != `DPoP error="use_dpop_nonce"` {
		t.Fatalf("WWW-Authenticate = %q, want %q", got, `DPoP error="use_dpop_nonce"`)
	}
}

func TestWriteJSONOmitsEmptyDescription(t *testing.T) {
	rec := httptest.NewRecorder()
	httperror.WriteJSON(rec, "", "", "invalid_request", "", 400)

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if _, ok := raw["error_description"]; ok {
		t.Fatalf("body = %s, want no error_description member for an empty description", rec.Body.Bytes())
	}
}

func TestIsErrorText(t *testing.T) {
	for s, want := range map[string]bool{
		"invalid_request": true, " !#[]~": true,
		"": false, `a"b`: false, `a\b`: false, "a\x1fb": false, "a\x7fb": false, "é": false,
	} {
		if got := httperror.IsErrorText(s); got != want {
			t.Errorf("IsErrorText(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestNormalize(t *testing.T) {
	for _, tc := range []struct {
		code, description string
		status            int
		allowEmpty        bool
		wantCode          string
		wantStatus        int
		wantDescription   string
	}{
		{"invalid_request", "d", 400, false, "invalid_request", 400, "d"},
		{"invalid_request", "d", 599, false, "invalid_request", 599, "d"},
		{"invalid_request", "d", 399, false, "server_error", 500, "d"},
		{"invalid_request", "d", 600, false, "server_error", 500, "d"},
		{"", "d", 401, false, "server_error", 500, "d"},
		{"", "d", 401, true, "", 401, "d"},
		{"", "", 0, true, "server_error", 500, ""},
		{`x"`, "d", 400, true, "server_error", 500, "d"},
		{"invalid_request", "\n", 400, false, "invalid_request", 400, ""},
	} {
		code, status, desc := httperror.Normalize(tc.code, tc.status, tc.description, tc.allowEmpty)
		if code != tc.wantCode || status != tc.wantStatus || desc != tc.wantDescription {
			t.Errorf("Normalize(%q, %d, %q, %v) = %q/%d/%q, want %q/%d/%q", tc.code, tc.status, tc.description, tc.allowEmpty, code, status, desc, tc.wantCode, tc.wantStatus, tc.wantDescription)
		}
	}
}

func TestStatus(t *testing.T) {
	for in, want := range map[int]int{0: 500, 200: 500, 399: 500, 400: 400, 599: 599, 600: 500} {
		if got := httperror.Status(in); got != want {
			t.Errorf("Status(%d) = %d, want %d", in, got, want)
		}
	}
}

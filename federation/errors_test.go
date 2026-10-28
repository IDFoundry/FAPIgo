package federation_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/idfoundry/fapigo/federation"
)

func TestErrorWriteJSON(t *testing.T) {
	err := federation.NewError(federation.ErrorNotFound, http.StatusNotFound, "no such subordinate")
	w := httptest.NewRecorder()
	err.WriteJSON(w)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
	if got := w.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	var body struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if body.Error != "not_found" || body.ErrorDescription != "no such subordinate" {
		t.Errorf("body = %+v, want error=not_found, error_description=\"no such subordinate\"", body)
	}
}

func TestErrorMessageIncludesCause(t *testing.T) {
	// NewError never sets a cause (see its own doc comment) — the only
	// way to exercise Error()'s "with cause" branch from this package's
	// public API is a real validation failure that wraps one, e.g.
	// SubjectFromFetchRequest's own ValidEntityID rejection.
	r := httptest.NewRequest(http.MethodGet, "https://ta.example.org/fetch?sub=not-a-url", nil)
	_, err := federation.SubjectFromFetchRequest(r)
	if err == nil {
		t.Fatal("SubjectFromFetchRequest(invalid sub) = nil error, want error")
	}
	if err.Error() == "" {
		t.Error("Error() = \"\", want a non-empty message including the underlying cause")
	}
	if errors.Unwrap(err) == nil {
		t.Error("Unwrap() = nil, want the underlying ValidEntityID error")
	}
}

func TestErrorAccessors(t *testing.T) {
	err := federation.NewError(federation.ErrorUnsupportedParameter, http.StatusBadRequest, "nope")
	if err.Code() != federation.ErrorUnsupportedParameter {
		t.Errorf("Code = %s, want unsupported_parameter", err.Code())
	}
	if err.PublicDescription() != "nope" {
		t.Errorf("PublicDescription = %q, want \"nope\"", err.PublicDescription())
	}
	if err.HTTPStatus() != http.StatusBadRequest {
		t.Errorf("HTTPStatus = %d, want 400", err.HTTPStatus())
	}
	if errors.Unwrap(err) != nil {
		t.Errorf("Unwrap = %v, want nil (NewError sets no cause)", errors.Unwrap(err))
	}
	if err.Error() == "" {
		t.Error("Error() = \"\", want a non-empty log message")
	}
}

// TestWriteErrorWithFederationError covers WriteError's main path: a
// *federation.Error (wrapped, since errors.As must unwrap it, not just
// type-assert) is encoded via its own WriteJSON.
func TestWriteErrorWithFederationError(t *testing.T) {
	err := federation.NewError(federation.ErrorNotFound, http.StatusNotFound, "no such subordinate")
	wrapped := fmt.Errorf("fetch failed: %w", err)

	rec := httptest.NewRecorder()
	federation.WriteError(rec, wrapped)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	var body struct {
		Error string `json:"error"`
	}
	if decodeErr := json.Unmarshal(rec.Body.Bytes(), &body); decodeErr != nil {
		t.Fatalf("unmarshal body: %v (body: %s)", decodeErr, rec.Body.Bytes())
	}
	if body.Error != string(federation.ErrorNotFound) {
		t.Fatalf("error = %q, want %q", body.Error, federation.ErrorNotFound)
	}
}

// TestWriteErrorFallsBackForUnknownError covers WriteError's other
// branch: an error that isn't (and doesn't wrap) a *federation.Error
// gets a generic 500.
func TestWriteErrorFallsBackForUnknownError(t *testing.T) {
	rec := httptest.NewRecorder()
	federation.WriteError(rec, errors.New("something unrelated failed"))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

// decodeFederationError checks w holds a §8.9 JSON error response with
// both REQUIRED members, and returns them.
func decodeFederationError(t *testing.T, w *httptest.ResponseRecorder) (code, description string) {
	t.Helper()
	if got := w.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal body %q: %v", w.Body.String(), err)
	}
	if body["error"] == "" || body["error_description"] == "" {
		t.Fatalf("body = %q, want both error and error_description", w.Body.String())
	}
	return body["error"], body["error_description"]
}

// TestWriteErrorIsAlwaysSection89JSON covers OpenID Federation 1.0
// §8.9: an error response body SHOULD be a JSON object with
// application/json, and its error_description is REQUIRED — for an
// error that isn't an *Error, and for one built with no description.
func TestWriteErrorIsAlwaysSection89JSON(t *testing.T) {
	w := httptest.NewRecorder()
	federation.WriteError(w, errors.New("database is down: secret detail"))
	code, description := decodeFederationError(t, w)
	if w.Code != http.StatusInternalServerError || code != "server_error" {
		t.Errorf("WriteError(plain error) = %d %s, want 500 server_error", w.Code, code)
	}
	if description == "database is down: secret detail" {
		t.Error("WriteError exposed the error's own message")
	}

	for _, c := range []federation.ErrorCode{
		federation.ErrorInvalidRequest, federation.ErrorNotFound, federation.ErrorServerError, federation.ErrorTemporarilyUnavailable,
		federation.ErrorInvalidClient, federation.ErrorInvalidIssuer, federation.ErrorInvalidSubject, federation.ErrorInvalidTrustAnchor,
		federation.ErrorInvalidTrustChain, federation.ErrorInvalidMetadata, federation.ErrorUnsupportedParameter,
	} {
		w := httptest.NewRecorder()
		federation.NewError(c, http.StatusBadRequest, "").WriteJSON(w)
		if got, _ := decodeFederationError(t, w); got != string(c) {
			t.Errorf("NewError(%s, \"\") wrote error %q", c, got)
		}
	}
	w = httptest.NewRecorder()
	(&federation.Error{}).WriteJSON(w)
	decodeFederationError(t, w)
}

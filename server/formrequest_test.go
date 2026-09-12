package server_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/idfoundry/fapigo/server"
)

func newFormPOST(t *testing.T, contentType, body string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "https://as.example.com/token", strings.NewReader(body))
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	return r
}

func TestFormRequestFromHTTPPreservesOrderAndDuplicates(t *testing.T) {
	r := newFormPOST(t, "application/x-www-form-urlencoded", "grant_type=client_credentials&scope=a+b&scope=c")
	form, err := server.FormRequestFromHTTP(r)
	if err != nil {
		t.Fatalf("FormRequestFromHTTP: %v", err)
	}
	want := []server.FormParameter{
		{Name: "grant_type", Value: "client_credentials"},
		{Name: "scope", Value: "a b"},
		{Name: "scope", Value: "c"},
	}
	if len(form.Parameters) != len(want) {
		t.Fatalf("Parameters = %v, want %v", form.Parameters, want)
	}
	for i, p := range form.Parameters {
		if p != want[i] {
			t.Errorf("Parameters[%d] = %+v, want %+v", i, p, want[i])
		}
	}
}

func TestFormRequestFromHTTPAcceptsContentTypeWithCharset(t *testing.T) {
	r := newFormPOST(t, "application/x-www-form-urlencoded; charset=UTF-8", "grant_type=refresh_token")
	if _, err := server.FormRequestFromHTTP(r); err != nil {
		t.Fatalf("FormRequestFromHTTP: %v", err)
	}
}

func TestFormRequestFromHTTPRejectsWrongContentType(t *testing.T) {
	r := newFormPOST(t, "application/json", `{"grant_type":"refresh_token"}`)
	if _, err := server.FormRequestFromHTTP(r); err == nil {
		t.Fatalf("FormRequestFromHTTP(wrong content type) = nil error, want error")
	}
}

func TestFormRequestFromHTTPRejectsMalformedParameterName(t *testing.T) {
	r := newFormPOST(t, "application/x-www-form-urlencoded", "%zz=value")
	if _, err := server.FormRequestFromHTTP(r); err == nil {
		t.Fatalf("FormRequestFromHTTP(malformed name) = nil error, want error")
	}
}

func TestFormRequestFromHTTPRejectsMalformedParameterValue(t *testing.T) {
	r := newFormPOST(t, "application/x-www-form-urlencoded", "grant_type=%zz")
	if _, err := server.FormRequestFromHTTP(r); err == nil {
		t.Fatalf("FormRequestFromHTTP(malformed value) = nil error, want error")
	}
}

func TestFormRequestFromHTTPRejectsOversizedBody(t *testing.T) {
	huge := "grant_type=" + strings.Repeat("a", 1<<20+1)
	r := newFormPOST(t, "application/x-www-form-urlencoded", huge)
	if _, err := server.FormRequestFromHTTP(r); err == nil {
		t.Fatalf("FormRequestFromHTTP(oversized body) = nil error, want error")
	}
}

func TestFormRequestFromHTTPAcceptsEmptyBody(t *testing.T) {
	r := newFormPOST(t, "application/x-www-form-urlencoded", "")
	form, err := server.FormRequestFromHTTP(r)
	if err != nil {
		t.Fatalf("FormRequestFromHTTP: %v", err)
	}
	if len(form.Parameters) != 0 {
		t.Fatalf("Parameters = %v, want empty", form.Parameters)
	}
}

// TestFormRequestGetReturnsFirstMatch covers Get's own first-match
// semantics, distinct from this package's internal duplicate-rejecting
// parameter handling — see Get's own doc comment for why that
// difference is deliberate.
func TestFormRequestGetReturnsFirstMatch(t *testing.T) {
	form := server.FormRequest{Parameters: []server.FormParameter{
		{Name: "grant_type", Value: "authorization_code"},
		{Name: "grant_type", Value: "refresh_token"},
		{Name: "code", Value: "abc123"},
	}}

	if got := form.Get("grant_type"); got != "authorization_code" {
		t.Fatalf("Get(grant_type) = %q, want %q (first occurrence)", got, "authorization_code")
	}
	if got := form.Get("code"); got != "abc123" {
		t.Fatalf("Get(code) = %q, want %q", got, "abc123")
	}
}

// TestFormRequestGetAbsentReturnsEmpty covers Get's other branch: a
// name that never appears returns "", not an error.
func TestFormRequestGetAbsentReturnsEmpty(t *testing.T) {
	form := server.FormRequest{Parameters: []server.FormParameter{
		{Name: "code", Value: "abc123"},
	}}

	if got := form.Get("grant_type"); got != "" {
		t.Fatalf("Get(grant_type) = %q, want \"\" for an absent parameter", got)
	}
}

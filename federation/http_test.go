package federation_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/idfoundry/fapigo/federation"
)

func TestSubjectFromFetchRequest(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "https://ta.example.org/fetch?sub=https%3A%2F%2Fle.example.org", nil)
	sub, err := federation.SubjectFromFetchRequest(r)
	if err != nil {
		t.Fatalf("SubjectFromFetchRequest: %v", err)
	}
	if sub != "https://le.example.org" {
		t.Errorf("sub = %q, want https://le.example.org", sub)
	}
}

func TestSubjectFromFetchRequestRejectsMissingSub(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "https://ta.example.org/fetch", nil)
	_, err := federation.SubjectFromFetchRequest(r)
	var fedErr *federation.Error
	if !errors.As(err, &fedErr) || fedErr.Code() != federation.ErrorInvalidRequest || fedErr.HTTPStatus() != http.StatusBadRequest {
		t.Errorf("error = %v, want a *federation.Error with code invalid_request/400", err)
	}
}

func TestSubjectFromFetchRequestRejectsInvalidSub(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "https://ta.example.org/fetch?sub=not-a-url", nil)
	_, err := federation.SubjectFromFetchRequest(r)
	var fedErr *federation.Error
	if !errors.As(err, &fedErr) || fedErr.Code() != federation.ErrorInvalidRequest {
		t.Errorf("error = %v, want a *federation.Error with code invalid_request", err)
	}
}

func TestRejectUnsupportedListingFiltersAllowsPlainRequest(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "https://ta.example.org/list", nil)
	if err := federation.RejectUnsupportedListingFilters(r); err != nil {
		t.Errorf("RejectUnsupportedListingFilters(no filters) = %v, want nil", err)
	}
}

func TestRejectUnsupportedListingFiltersRejectsEachFilter(t *testing.T) {
	for _, param := range []string{"entity_type", "trust_marked", "trust_mark_type", "intermediate"} {
		t.Run(param, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "https://ta.example.org/list?"+param+"=x", nil)
			err := federation.RejectUnsupportedListingFilters(r)
			var fedErr *federation.Error
			if !errors.As(err, &fedErr) || fedErr.Code() != federation.ErrorUnsupportedParameter || fedErr.HTTPStatus() != http.StatusBadRequest {
				t.Errorf("error = %v, want a *federation.Error with code unsupported_parameter/400", err)
			}
		})
	}
}

func postFormRequest(t *testing.T, url, body string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, url, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

func TestTrustMarkFromStatusRequest(t *testing.T) {
	r := postFormRequest(t, "https://issuer.example.org/status", "trust_mark=a.b.c")
	trustMark, err := federation.TrustMarkFromStatusRequest(r)
	if err != nil {
		t.Fatalf("TrustMarkFromStatusRequest: %v", err)
	}
	if trustMark != "a.b.c" {
		t.Errorf("trustMark = %q, want \"a.b.c\"", trustMark)
	}
}

func TestTrustMarkFromStatusRequestRejectsMissing(t *testing.T) {
	r := postFormRequest(t, "https://issuer.example.org/status", "")
	_, err := federation.TrustMarkFromStatusRequest(r)
	var fedErr *federation.Error
	if !errors.As(err, &fedErr) || fedErr.Code() != federation.ErrorInvalidRequest || fedErr.HTTPStatus() != http.StatusBadRequest {
		t.Errorf("error = %v, want a *federation.Error with code invalid_request/400", err)
	}
}

func TestTrustMarkListingFilters(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "https://issuer.example.org/list?trust_mark_type=https%3A%2F%2Ffederation.example.org%2Fmarks%2Fcertified&sub=https%3A%2F%2Frp.example.org", nil)
	trustMarkType, subject, err := federation.TrustMarkListingFilters(r)
	if err != nil {
		t.Fatalf("TrustMarkListingFilters: %v", err)
	}
	if trustMarkType != "https://federation.example.org/marks/certified" {
		t.Errorf("trustMarkType = %q", trustMarkType)
	}
	if subject != "https://rp.example.org" {
		t.Errorf("subject = %q", subject)
	}
}

func TestTrustMarkListingFiltersAllowsMissingSub(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "https://issuer.example.org/list?trust_mark_type=https%3A%2F%2Ffederation.example.org%2Fmarks%2Fcertified", nil)
	trustMarkType, subject, err := federation.TrustMarkListingFilters(r)
	if err != nil {
		t.Fatalf("TrustMarkListingFilters: %v", err)
	}
	if trustMarkType == "" {
		t.Error("trustMarkType is empty, want the query value")
	}
	if subject != "" {
		t.Errorf("subject = %q, want empty", subject)
	}
}

func TestTrustMarkListingFiltersRejectsMissingType(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "https://issuer.example.org/list", nil)
	_, _, err := federation.TrustMarkListingFilters(r)
	var fedErr *federation.Error
	if !errors.As(err, &fedErr) || fedErr.Code() != federation.ErrorInvalidRequest || fedErr.HTTPStatus() != http.StatusBadRequest {
		t.Errorf("error = %v, want a *federation.Error with code invalid_request/400", err)
	}
}

func TestTrustMarkListingFiltersRejectsInvalidSub(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "https://issuer.example.org/list?trust_mark_type=x&sub=not-a-url", nil)
	_, _, err := federation.TrustMarkListingFilters(r)
	var fedErr *federation.Error
	if !errors.As(err, &fedErr) || fedErr.Code() != federation.ErrorInvalidRequest {
		t.Errorf("error = %v, want a *federation.Error with code invalid_request", err)
	}
}

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

func TestSubordinateListingFiltersFromRequestAllowsPlainRequest(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "https://ta.example.org/list", nil)
	filters, err := federation.SubordinateListingFiltersFromRequest(r)
	if err != nil {
		t.Fatalf("SubordinateListingFiltersFromRequest: %v", err)
	}
	if len(filters.EntityTypes) != 0 || filters.TrustMarkedSet || filters.TrustMarkType != "" || filters.IntermediateSet {
		t.Errorf("filters = %+v, want every field at its zero value", filters)
	}
}

func TestSubordinateListingFiltersFromRequestParsesEveryFilter(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "https://ta.example.org/list?entity_type=openid_provider&entity_type=openid_relying_party&trust_marked=true&trust_mark_type=https%3A%2F%2Ffederation.example.org%2Fmarks%2Fcertified&intermediate=false", nil)
	filters, err := federation.SubordinateListingFiltersFromRequest(r)
	if err != nil {
		t.Fatalf("SubordinateListingFiltersFromRequest: %v", err)
	}
	if len(filters.EntityTypes) != 2 || filters.EntityTypes[0] != "openid_provider" || filters.EntityTypes[1] != "openid_relying_party" {
		t.Errorf("EntityTypes = %v, want [openid_provider openid_relying_party]", filters.EntityTypes)
	}
	if !filters.TrustMarkedSet || !filters.TrustMarked {
		t.Errorf("TrustMarked/TrustMarkedSet = %v/%v, want true/true", filters.TrustMarked, filters.TrustMarkedSet)
	}
	if filters.TrustMarkType != "https://federation.example.org/marks/certified" {
		t.Errorf("TrustMarkType = %q", filters.TrustMarkType)
	}
	if !filters.IntermediateSet || filters.Intermediate {
		t.Errorf("Intermediate/IntermediateSet = %v/%v, want false/true", filters.Intermediate, filters.IntermediateSet)
	}
}

func TestSubordinateListingFiltersFromRequestRejectsInvalidBoolean(t *testing.T) {
	for _, param := range []string{"trust_marked", "intermediate"} {
		t.Run(param, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "https://ta.example.org/list?"+param+"=yes", nil)
			_, err := federation.SubordinateListingFiltersFromRequest(r)
			var fedErr *federation.Error
			if !errors.As(err, &fedErr) || fedErr.Code() != federation.ErrorInvalidRequest || fedErr.HTTPStatus() != http.StatusBadRequest {
				t.Errorf("error = %v, want a *federation.Error with code invalid_request/400", err)
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

func TestTrustMarkRequestFromHTTP(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "https://issuer.example.org/trust_mark?trust_mark_type=https%3A%2F%2Ffederation.example.org%2Fmarks%2Fcertified&sub=https%3A%2F%2Frp.example.org", nil)
	trustMarkType, subject, err := federation.TrustMarkRequestFromHTTP(r)
	if err != nil {
		t.Fatalf("TrustMarkRequestFromHTTP: %v", err)
	}
	if trustMarkType != "https://federation.example.org/marks/certified" {
		t.Errorf("trustMarkType = %q", trustMarkType)
	}
	if subject != "https://rp.example.org" {
		t.Errorf("subject = %q", subject)
	}
}

func TestTrustMarkRequestFromHTTPRejectsMissingType(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "https://issuer.example.org/trust_mark?sub=https%3A%2F%2Frp.example.org", nil)
	_, _, err := federation.TrustMarkRequestFromHTTP(r)
	var fedErr *federation.Error
	if !errors.As(err, &fedErr) || fedErr.Code() != federation.ErrorInvalidRequest || fedErr.HTTPStatus() != http.StatusBadRequest {
		t.Errorf("error = %v, want a *federation.Error with code invalid_request/400", err)
	}
}

func TestTrustMarkRequestFromHTTPRejectsMissingSub(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "https://issuer.example.org/trust_mark?trust_mark_type=x", nil)
	_, _, err := federation.TrustMarkRequestFromHTTP(r)
	var fedErr *federation.Error
	if !errors.As(err, &fedErr) || fedErr.Code() != federation.ErrorInvalidRequest || fedErr.HTTPStatus() != http.StatusBadRequest {
		t.Errorf("error = %v, want a *federation.Error with code invalid_request/400", err)
	}
}

func TestTrustMarkRequestFromHTTPRejectsInvalidSub(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "https://issuer.example.org/trust_mark?trust_mark_type=x&sub=not-a-url", nil)
	_, _, err := federation.TrustMarkRequestFromHTTP(r)
	var fedErr *federation.Error
	if !errors.As(err, &fedErr) || fedErr.Code() != federation.ErrorInvalidRequest {
		t.Errorf("error = %v, want a *federation.Error with code invalid_request", err)
	}
}

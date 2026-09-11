package federation_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
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

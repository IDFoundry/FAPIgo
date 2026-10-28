package server_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/idfoundry/fapigo/server"
)

func TestBeginAuthorizationRequestFromHTTP(t *testing.T) {
	r := httptest.NewRequest("GET", "/authorize?client_id=client-1&request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Aabc&ui_locales=en", nil)
	got, err := server.BeginAuthorizationRequestFromHTTP(r)
	if err != nil {
		t.Fatalf("BeginAuthorizationRequestFromHTTP: %v", err)
	}
	if got.ClientID != "client-1" || got.RequestURI != "urn:ietf:params:oauth:request_uri:abc" {
		t.Errorf("got %+v", got)
	}

	// Missing values are BeginAuthorization's to answer.
	if got, err := server.BeginAuthorizationRequestFromHTTP(httptest.NewRequest("GET", "/authorize", nil)); err != nil || got != (server.BeginAuthorizationRequest{}) {
		t.Errorf("no parameters = %+v, %v; want empty values and no error", got, err)
	}
}

func TestBeginAuthorizationRequestFromHTTPRefuses(t *testing.T) {
	for name, query := range map[string]string{
		"repeated request_uri": "client_id=c&request_uri=urn%3Aa&request_uri=urn%3Ab",
		"repeated client_id":   "client_id=c&client_id=d&request_uri=urn%3Aa",
		"malformed query":      "client_id=%zz",
	} {
		r := httptest.NewRequest("GET", "/authorize", nil)
		r.URL.RawQuery = query
		_, err := server.BeginAuthorizationRequestFromHTTP(r)
		if code := serverErrorCode(t, err); code != server.ErrorInvalidRequest {
			t.Errorf("%s: error code %q, want %q", name, code, server.ErrorInvalidRequest)
		}
	}
}

// OIDC Core §3.1.2.1: an authorization server "MUST support the use of
// the HTTP GET and POST methods", a POST's parameters form-serialized.
// A POST is read from its body alone, under FormRequestFromHTTP's rules.
func TestBeginAuthorizationRequestFromHTTPReadsAPostedForm(t *testing.T) {
	body := "client_id=client-1&request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Aabc"
	r := httptest.NewRequest(http.MethodPost, "/authorize?client_id=from-query", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	got, err := server.BeginAuthorizationRequestFromHTTP(r)
	if err != nil {
		t.Fatalf("BeginAuthorizationRequestFromHTTP(POST): %v", err)
	}
	if got.ClientID != "client-1" || got.RequestURI != "urn:ietf:params:oauth:request_uri:abc" {
		t.Errorf("got %+v, want the body's client_id and request_uri", got)
	}
}

func TestBeginAuthorizationRequestFromHTTPRefusesAPostedForm(t *testing.T) {
	for name, tc := range map[string]struct{ contentType, body string }{
		"repeated request_uri": {"application/x-www-form-urlencoded", "client_id=c&request_uri=urn%3Aa&request_uri=urn%3Ab"},
		"repeated client_id":   {"application/x-www-form-urlencoded", "client_id=c&client_id=d&request_uri=urn%3Aa"},
		"malformed body":       {"application/x-www-form-urlencoded", "client_id=%zz"},
		"not form-encoded":     {"application/json", `{"client_id":"c"}`},
		"too large":            {"application/x-www-form-urlencoded", "client_id=" + strings.Repeat("a", 1<<20)},
	} {
		r := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader(tc.body))
		r.Header.Set("Content-Type", tc.contentType)
		_, err := server.BeginAuthorizationRequestFromHTTP(r)
		if err == nil {
			t.Errorf("%s: no error, want invalid_request", name)
			continue
		}
		if code := serverErrorCode(t, err); code != server.ErrorInvalidRequest {
			t.Errorf("%s: error code %q, want %q", name, code, server.ErrorInvalidRequest)
		}
	}
}

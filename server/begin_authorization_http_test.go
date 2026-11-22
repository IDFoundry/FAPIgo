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
		// As url.ParseQuery has it: no parameter separator, but malformed.
		"semicolon":            "client_id=c;request_uri=urn%3Aa",
		"too many parameters":  "client_id=c&request_uri=urn%3Aa&" + numberedForm(99, "&"),
		"many tiny parameters": strings.Repeat("a&", 1<<19),
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
		"too many parameters":  {"application/x-www-form-urlencoded", "client_id=c&request_uri=urn%3Aa&" + numberedForm(99, "&")},
		"many tiny parameters": {"application/x-www-form-urlencoded", strings.Repeat("a&", 1<<19)},
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

// TestBeginAuthorizationRequestFromHTTPTakesTheParameterBound: a query,
// like a posted form, may carry 100 parameters — counted as a body's
// are, so the empty pairs between them are none — and its values are
// read from among them.
func TestBeginAuthorizationRequestFromHTTPTakesTheParameterBound(t *testing.T) {
	parameters := "client_id=client-1&&request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Aabc&&" + numberedForm(98, "&&")
	query := httptest.NewRequest(http.MethodGet, "/authorize", nil)
	query.URL.RawQuery = parameters
	posted := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader(parameters))
	posted.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, r := range []*http.Request{query, posted} {
		got, err := server.BeginAuthorizationRequestFromHTTP(r)
		if err != nil {
			t.Fatalf("BeginAuthorizationRequestFromHTTP(%s, 100 parameters): %v", r.Method, err)
		}
		if got.ClientID != "client-1" || got.RequestURI != "urn:ietf:params:oauth:request_uri:abc" {
			t.Errorf("%s: got %+v, want the request's client_id and request_uri", r.Method, got)
		}
	}
}

// TestBeginAuthorizationRequestFromHTTPAllocationIsBounded: refusing a
// 1 MiB posted form of 524,288 one-byte parameters costs about what
// reading it does, not a url.Values entry for every one of them.
func TestBeginAuthorizationRequestFromHTTPAllocationIsBounded(t *testing.T) {
	body := strings.Repeat("a&", 1<<19)
	allocated := bytesAllocated(4, func() {
		r := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		_, _ = server.BeginAuthorizationRequestFromHTTP(r)
	})
	if allocated > 8<<20 {
		t.Errorf("BeginAuthorizationRequestFromHTTP allocated %d bytes for a 1 MiB form, want at most 8 MiB", allocated)
	}
}

package server_test

import (
	"net/http/httptest"
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

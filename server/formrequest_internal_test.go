package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unsafe"
)

// sharesMemory reports whether s lies within within's bytes: a
// substring of it, keeping all of it alive, rather than a copy.
func sharesMemory(s, within string) bool {
	if s == "" || within == "" {
		return false
	}
	start := uintptr(unsafe.Pointer(unsafe.StringData(within)))
	p := uintptr(unsafe.Pointer(unsafe.StringData(s)))
	return p >= start && p < start+uintptr(len(within))
}

// TestDecodeFormParametersCopiesOut: no name or value
// decodeFormParameters returns shares memory with what it decoded,
// whether it was escaped or not, so a value kept (a client_id cached as
// a key, say) doesn't keep a whole request body or query alive.
func TestDecodeFormParametersCopiesOut(t *testing.T) {
	encoded := "client_id=client-1&request_uri=urn%3Aexample%3Aabc&scope=openid+accounts&pad=" + strings.Repeat("a", 1<<16)
	params, err := decodeFormParameters(encoded, "the request body")
	if err != nil {
		t.Fatalf("decodeFormParameters: %v", err)
	}
	want := []FormParameter{
		{Name: "client_id", Value: "client-1"},
		{Name: "request_uri", Value: "urn:example:abc"},
		{Name: "scope", Value: "openid accounts"},
		{Name: "pad", Value: strings.Repeat("a", 1<<16)},
	}
	if len(params) != len(want) {
		t.Fatalf("decoded %d parameters, want %d", len(params), len(want))
	}
	for i, p := range params {
		if p != want[i] {
			t.Errorf("parameter %d = %.40q=%.40q, want %.40q=%.40q", i, p.Name, p.Value, want[i].Name, want[i].Value)
		}
		for _, s := range []string{p.Name, p.Value} {
			if sharesMemory(s, encoded) {
				t.Errorf("%.40q shares the encoded form's memory, want a copy", s)
			}
		}
	}
}

// TestBeginAuthorizationRequestFromHTTPCopiesOutOfTheQuery: the values
// read from a GET's query share no memory with it either — the query
// is the request line, which a client_id the client repository caches
// would otherwise keep alive.
func TestBeginAuthorizationRequestFromHTTPCopiesOutOfTheQuery(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/authorize", nil)
	r.URL.RawQuery = "client_id=client-1&request_uri=urn:ietf:params:oauth:request_uri:abc&request=eyJhbGciOiJFUzI1NiJ9.e30.c2ln&pad=" + strings.Repeat("a", 1<<16)
	req, err := BeginAuthorizationRequestFromHTTP(r)
	if err != nil {
		t.Fatalf("BeginAuthorizationRequestFromHTTP: %v", err)
	}
	if req.ClientID != "client-1" || req.RequestURI != "urn:ietf:params:oauth:request_uri:abc" || req.Request != "eyJhbGciOiJFUzI1NiJ9.e30.c2ln" {
		t.Fatalf("got %+v", req)
	}
	for name, s := range map[string]string{"ClientID": req.ClientID.String(), "RequestURI": req.RequestURI, "Request": req.Request} {
		if sharesMemory(s, r.URL.RawQuery) {
			t.Errorf("%s shares the query's memory, want a copy", name)
		}
	}
}

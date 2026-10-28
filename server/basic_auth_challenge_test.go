package server_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/server"
)

func basicAuthTokenRequest(body string, configure func(*http.Request)) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "https://as.example/token", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	configure(r)
	return r
}

// RFC 6749 §5.2: a client that "attempted to authenticate via the
// Authorization request header field" gets a 401 with "the
// WWW-Authenticate response header field matching the authentication
// scheme used by the client".
func TestTokenEndpointChallengesAuthorizationHeaderAuthentication(t *testing.T) {
	const body = "grant_type=authorization_code&client_id=client-1&code=x&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&code_verifier=v"
	for name, tc := range map[string]struct {
		configure func(*http.Request)
		scheme    string
	}{
		"basic":   {func(r *http.Request) { r.SetBasicAuth("client-1", "secret") }, "Basic"},
		"other":   {func(r *http.Request) { r.Header.Set("Authorization", "Bearer abc") }, "Bearer"},
		"garbled": {func(r *http.Request) { r.Header.Set("Authorization", `"x" y`) }, "Basic"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := server.TokenEndpointRequestFromHTTP(basicAuthTokenRequest(body, tc.configure))
			if err == nil {
				t.Fatal("TokenEndpointRequestFromHTTP = nil error, want invalid_client")
			}
			rec := httptest.NewRecorder()
			server.WriteError(rec, err)
			if rec.Code != http.StatusUnauthorized || serverErrorCode(t, err) != server.ErrorInvalidClient {
				t.Fatalf("status %d, code %q; want 401 invalid_client", rec.Code, serverErrorCode(t, err))
			}
			if got := rec.Header().Get("WWW-Authenticate"); !strings.HasPrefix(got, tc.scheme+" realm=") {
				t.Fatalf("WWW-Authenticate = %q, want a %s challenge", got, tc.scheme)
			}
		})
	}
}

// A request that also carries a credential this server takes is
// authenticated by it, as before.
func TestTokenEndpointIgnoresAuthorizationHeaderBesideAnAssertion(t *testing.T) {
	body := "grant_type=authorization_code&code=x&client_assertion_type=" + clientassertion.AssertionType + "&client_assertion=a.b.c"
	if _, err := server.TokenEndpointRequestFromHTTP(basicAuthTokenRequest(body, func(r *http.Request) { r.SetBasicAuth("client-1", "secret") })); err != nil {
		t.Fatalf("TokenEndpointRequestFromHTTP: %v", err)
	}
	if _, err := server.TokenEndpointRequestFromHTTP(basicAuthTokenRequest("grant_type=authorization_code", func(*http.Request) {})); err != nil {
		t.Fatalf("TokenEndpointRequestFromHTTP(no Authorization header): %v", err)
	}
}

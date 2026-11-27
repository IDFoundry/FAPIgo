package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/idfoundry/fapigo/server"
)

// TestListenerHandlerMarksTheRoute: a request each listener accepts is
// read with that listener's endpoint route, which decides the URL its
// DPoP proof must name.
func TestListenerHandlerMarksTheRoute(t *testing.T) {
	for _, route := range []server.EndpointRoute{server.PrimaryEndpoint, server.MTLSEndpointAlias} {
		var got server.EndpointRoute
		h := listenerHandler(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			req, err := server.PushAuthorizationRequestFromHTTP(r)
			if err != nil {
				t.Fatalf("PushAuthorizationRequestFromHTTP: %v", err)
			}
			got = req.HTTP.EndpointRoute
		}), route, "https://as.example")
		r := httptest.NewRequest(http.MethodPost, "/par", strings.NewReader("client_id=c"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		h.ServeHTTP(httptest.NewRecorder(), r)
		if got != route {
			t.Errorf("listener %v: request read with route %v", route, got)
		}
	}
}

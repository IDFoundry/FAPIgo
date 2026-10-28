package fapihttp_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"

	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/resource"
)

// NewClient builds the transport, an *http.Client that refuses private,
// loopback and link-local addresses when it dials; New wraps it into the
// fetcher that discovery, JWKS and federation fetches take. The presets
// set every required limit.
func ExampleNew() {
	transport, err := fapihttp.NewClient(fapihttp.RecommendedTransportConfig())
	if err != nil {
		fmt.Println(err)
		return
	}
	fetcher, err := fapihttp.New(transport, fapihttp.RecommendedConfig())
	if err != nil {
		fmt.Println(err)
		return
	}
	// client.Dependencies.HTTP takes transport; client.Discover and
	// keys.NewJWKSIssuerKeySource take fetcher.
	fmt.Println("loopback allowed:", fetcher.AllowsLoopback())
	// Output:
	// loopback allowed: false
}

// Behind a TLS-terminating proxy at 10.0.0.5, a resource server takes
// the client certificate from the proxy's RFC 9440 Client-Cert header,
// and refuses a request that didn't come from the proxy.
func ExampleForwardedClientCertificate() {
	fromProxy := fapihttp.RemoteAddrIn(netip.MustParsePrefix("10.0.0.5/32"))
	handler := func(w http.ResponseWriter, r *http.Request) {
		cert, err := fapihttp.ForwardedClientCertificate(r, fapihttp.ClientCertHeader, fromProxy)
		if err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		req := resource.VerifyRequestFromHTTP(r)
		req.PeerCertificate = cert
		// authz, err := verifier.Verify(r.Context(), req) ...
	}
	r := httptest.NewRequest(http.MethodGet, "https://api.example.com/accounts", nil)
	r.RemoteAddr = "203.0.113.9:4711" // a client, not the proxy
	r.Header.Set("Client-Cert", ":MIIB...:")
	rec := httptest.NewRecorder()
	handler(rec, r)
	fmt.Println(rec.Code)
	// Output:
	// 403
}

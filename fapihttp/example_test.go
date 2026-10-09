package fapihttp_test

import (
	"fmt"

	"github.com/idfoundry/fapigo/fapihttp"
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

package resource_test

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/idfoundry/fapigo/resource"
)

// TestFromHTTPAdaptersAllocationBudgets bounds the allocations each of
// the resource package's *FromHTTP adapters makes taking a typical
// protected-resource request (a DPoP-bound access token over mTLS), so
// a change that starts allocating per byte or per header shows up here
// before it shows up as a denial of service. Each budget is about twice
// what was measured (go1.26, darwin/amd64), given in its comment.
func TestFromHTTPAdaptersAllocationBudgets(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "https://rs.example.com/accounts/%7Bid%7D?limit=10", nil)
	r.Header.Set("Authorization", "DPoP "+strings.Repeat("t", 800))
	r.Header["DPoP"] = []string{strings.Repeat("d", 600)}
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Raw: []byte{1}}}}
	for name, tc := range map[string]struct {
		adapt  func()
		budget float64
	}{
		// Measured 2.
		"VerifyRequestFromHTTP": {adapt: func() { _ = resource.VerifyRequestFromHTTP(r) }, budget: 4},
		// Measured 1.
		"DPoPProofsFromHTTP": {adapt: func() { _ = resource.DPoPProofsFromHTTP(r) }, budget: 2},
		// Measured 0.
		"PeerCertificateFromHTTP": {adapt: func() { _ = resource.PeerCertificateFromHTTP(r) }, budget: 1},
	} {
		allocs := testing.AllocsPerRun(100, tc.adapt)
		t.Logf("%s: %.0f allocations", name, allocs)
		if allocs > tc.budget {
			t.Errorf("%s allocated %.0f times taking a typical request, want at most %.0f", name, allocs, tc.budget)
		}
	}
}

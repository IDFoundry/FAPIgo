package server_test

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/idfoundry/fapigo/server"
)

// fromHTTPAllocsCase is one TestFromHTTPAdaptersAllocationBudgets case:
// the request an adapter takes, rebuilt for each run since reading the
// body consumes it, and the most allocations one call may make.
type fromHTTPAllocsCase struct {
	method, target, body string
	header               http.Header
	tls                  *tls.ConnectionState
	adapt                func(*http.Request)
	budget               float64
}

// pushedFormBody is a pushed authorization request's form, of the size
// and shape a FAPI 2.0 client sends: its parameters with a client
// assertion.
var pushedFormBody = url.Values{
	"response_type":         {"code"},
	"client_id":             {"client-1"},
	"redirect_uri":          {"https://rp.example.com/cb"},
	"scope":                 {"openid accounts"},
	"state":                 {"af0ifjsldkj"},
	"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
	"code_challenge_method": {"S256"},
	"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
	"client_assertion":      {strings.Repeat("a", 600)},
}.Encode()

// TestFromHTTPAdaptersAllocationBudgets bounds the allocations each of
// the server's *FromHTTP adapters makes taking a typical request, so a
// change that starts allocating per byte, per parameter or per header
// shows up here before it shows up as a denial of service. Each budget
// is about twice what was measured (go1.26, darwin/amd64), given in its
// comment; rebuilding the request for each call isn't counted.
func TestFromHTTPAdaptersAllocationBudgets(t *testing.T) {
	form := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}
	withProofs := http.Header{
		"Content-Type":                 {"application/x-www-form-urlencoded"},
		"Dpop":                         {strings.Repeat("d", 600)},
		"Oauth-Client-Attestation":     {strings.Repeat("a", 600)},
		"Oauth-Client-Attestation-Pop": {strings.Repeat("p", 600)},
	}
	peer := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Raw: []byte{1}}}}
	cases := map[string]fromHTTPAllocsCase{
		// Measured 29.
		"FormRequestFromHTTP": {method: http.MethodPost, body: pushedFormBody, header: form, budget: 60,
			adapt: func(r *http.Request) { _, _ = server.FormRequestFromHTTP(r) }},
		// Measured 32.
		"PushAuthorizationRequestFromHTTP": {method: http.MethodPost, body: pushedFormBody, header: withProofs, tls: peer, budget: 64,
			adapt: func(r *http.Request) { _, _ = server.PushAuthorizationRequestFromHTTP(r) }},
		// Measured 32.
		"BeginBackchannelAuthenticationRequestFromHTTP": {method: http.MethodPost, body: pushedFormBody, header: withProofs, budget: 64,
			adapt: func(r *http.Request) { _, _ = server.BeginBackchannelAuthenticationRequestFromHTTP(r) }},
		// Measured 19.
		"TokenEndpointRequestFromHTTP": {method: http.MethodPost, body: "grant_type=authorization_code&code=" + strings.Repeat("c", 43) + "&redirect_uri=https%3A%2F%2Frp.example.com%2Fcb&code_verifier=" + strings.Repeat("v", 43), header: withProofs, budget: 40,
			adapt: func(r *http.Request) { _, _ = server.TokenEndpointRequestFromHTTP(r) }},
		// Measured 12.
		"TokenRevocationRequestFromHTTP": {method: http.MethodPost, body: "token=" + strings.Repeat("r", 43) + "&token_type_hint=refresh_token", header: withProofs, budget: 24,
			adapt: func(r *http.Request) { _, _ = server.TokenRevocationRequestFromHTTP(r) }},
		// Measured 9.
		"BeginAuthorizationRequestFromHTTP GET": {method: http.MethodGet, target: "/authorize?client_id=client-1&request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3A" + strings.Repeat("u", 43), budget: 20,
			adapt: func(r *http.Request) { _, _ = server.BeginAuthorizationRequestFromHTTP(r) }},
		// Measured 13.
		"BeginAuthorizationRequestFromHTTP POST": {method: http.MethodPost, body: "client_id=client-1&request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3A" + strings.Repeat("u", 43), header: form, budget: 28,
			adapt: func(r *http.Request) { _, _ = server.BeginAuthorizationRequestFromHTTP(r) }},
		// Measured 1.
		"DPoPProofsFromHTTP": {method: http.MethodPost, header: withProofs, budget: 2,
			adapt: func(r *http.Request) { _ = server.DPoPProofsFromHTTP(r) }},
		// Measured 2.
		"ClientAttestationHeadersFromHTTP": {method: http.MethodPost, header: withProofs, budget: 4,
			adapt: func(r *http.Request) { _, _ = server.ClientAttestationHeadersFromHTTP(r) }},
		// Measured 0.
		"PeerCertificateFromHTTP": {method: http.MethodPost, tls: peer, budget: 1,
			adapt: func(r *http.Request) { _ = server.PeerCertificateFromHTTP(r) }},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			allocs := adapterAllocs(tc, tc.adapt) - adapterAllocs(tc, func(*http.Request) {})
			t.Logf("%s: %.0f allocations", name, allocs)
			if allocs > tc.budget {
				t.Errorf("%s allocated %.0f times taking a typical request, want at most %.0f", name, allocs, tc.budget)
			}
		})
	}
}

// adapterAllocs is the allocations one call to adapt makes on tc's
// request, counting the rebuilding of the request and its body.
func adapterAllocs(tc fromHTTPAllocsCase, adapt func(*http.Request)) float64 {
	target := tc.target
	if target == "" {
		target = "/endpoint"
	}
	base := httptest.NewRequest(tc.method, target, nil)
	base.Header, base.TLS = tc.header, tc.tls
	if base.Header == nil {
		base.Header = http.Header{}
	}
	reader := strings.NewReader(tc.body)
	return testing.AllocsPerRun(100, func() {
		reader.Reset(tc.body)
		r := *base
		r.Body = io.NopCloser(reader)
		adapt(&r)
	})
}

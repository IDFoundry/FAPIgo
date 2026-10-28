package resource_test

import (
	"crypto/tls"
	"crypto/x509"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/idfoundry/fapigo/resource"
)

func TestVerifyRequestFromHTTP(t *testing.T) {
	cert := &x509.Certificate{Raw: []byte("client certificate")}
	r := httptest.NewRequest("POST", "https://attacker.example/accounts?x=1", nil)
	r.Header.Set("Authorization", "DPoP token-1")
	r.Header.Add("DPoP", "proof-1")
	r.Header.Add("DPoP", "proof-2")
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}

	got := resource.VerifyRequestFromHTTP(r)

	if got.Method != "POST" || got.Authorization != "DPoP token-1" {
		t.Errorf("Method %q, Authorization %q", got.Method, got.Authorization)
	}
	// Every DPoP header, so Verify can refuse more than one.
	if !slices.Equal(got.DPoPProofs, []string{"proof-1", "proof-2"}) {
		t.Errorf("DPoPProofs = %v, want both headers", got.DPoPProofs)
	}
	if got.PeerCertificate != cert {
		t.Error("PeerCertificate isn't the connection's client certificate")
	}
	// No URL from the request's Host: Verify builds it from
	// Config.ResourceURLs.
	if got.URL != nil {
		t.Errorf("URL = %s, want nil", got.URL)
	}
}

func TestVerifyRequestFromHTTPWithoutTLS(t *testing.T) {
	got := resource.VerifyRequestFromHTTP(httptest.NewRequest("GET", "/accounts", nil))
	if got.PeerCertificate != nil || got.URL != nil || len(got.DPoPProofs) != 0 {
		t.Errorf("got %+v, want no certificate, URL or proofs", got)
	}
}

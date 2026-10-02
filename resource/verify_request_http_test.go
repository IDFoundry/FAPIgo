package resource_test

import (
	"crypto/tls"
	"crypto/x509"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"

	"github.com/idfoundry/fapigo/resource"
)

func TestVerifyRequestFromHTTP(t *testing.T) {
	target, err := url.Parse("https://api.example.com/accounts")
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{Raw: []byte("client certificate")}
	r := httptest.NewRequest("POST", "https://attacker.example/accounts?x=1", nil)
	r.Header.Set("Authorization", "DPoP token-1")
	r.Header.Add("DPoP", "proof-1")
	r.Header.Add("DPoP", "proof-2")
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}

	got := resource.VerifyRequestFromHTTP(r, target)

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
	// The endpoint's own URL, never the request's Host.
	if got.URL.String() != "https://api.example.com/accounts" {
		t.Errorf("URL = %s, want the target", got.URL)
	}
	got.URL.Path = "/changed"
	if target.Path != "/accounts" {
		t.Error("VerifyRequestFromHTTP's URL aliases target")
	}
}

func TestVerifyRequestFromHTTPWithoutTLSOrTarget(t *testing.T) {
	got := resource.VerifyRequestFromHTTP(httptest.NewRequest("GET", "/accounts", nil), nil)
	if got.PeerCertificate != nil || got.URL != nil || len(got.DPoPProofs) != 0 {
		t.Errorf("got %+v, want no certificate, URL or proofs", got)
	}
}

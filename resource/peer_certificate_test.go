package resource_test

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/idfoundry/fapigo/resource"
)

func TestPeerCertificateFromHTTPReturnsPresentedCertificate(t *testing.T) {
	cert := selfSignedTestClientCert(t, "test-client")
	r := httptest.NewRequest(http.MethodGet, "https://rs.example.com/accounts", nil)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}

	got := resource.PeerCertificateFromHTTP(r)
	if got != cert {
		t.Fatalf("PeerCertificateFromHTTP = %v, want the presented certificate", got)
	}
}

func TestPeerCertificateFromHTTPNilWhenNotTLS(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "https://rs.example.com/accounts", nil)

	if got := resource.PeerCertificateFromHTTP(r); got != nil {
		t.Fatalf("PeerCertificateFromHTTP(non-TLS request) = %v, want nil", got)
	}
}

func TestPeerCertificateFromHTTPNilWhenNoneRequested(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "https://rs.example.com/accounts", nil)
	r.TLS = &tls.ConnectionState{}

	if got := resource.PeerCertificateFromHTTP(r); got != nil {
		t.Fatalf("PeerCertificateFromHTTP(TLS without a client certificate) = %v, want nil", got)
	}
}

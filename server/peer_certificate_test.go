package server_test

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/idfoundry/fapigo/server"
)

func TestPeerCertificateFromHTTPReturnsPresentedCertificate(t *testing.T) {
	cert := selfSignedTestClientCert(t)
	r := httptest.NewRequest(http.MethodPost, "https://as.example.com/token", nil)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}

	got := server.PeerCertificateFromHTTP(r)
	if got != cert {
		t.Fatalf("PeerCertificateFromHTTP = %v, want the presented certificate", got)
	}
}

func TestPeerCertificateFromHTTPNilWhenNotTLS(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "https://as.example.com/token", nil)

	if got := server.PeerCertificateFromHTTP(r); got != nil {
		t.Fatalf("PeerCertificateFromHTTP(non-TLS request) = %v, want nil", got)
	}
}

func TestPeerCertificateFromHTTPNilWhenNoneRequested(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "https://as.example.com/token", nil)
	r.TLS = &tls.ConnectionState{}

	if got := server.PeerCertificateFromHTTP(r); got != nil {
		t.Fatalf("PeerCertificateFromHTTP(TLS without a client certificate) = %v, want nil", got)
	}
}

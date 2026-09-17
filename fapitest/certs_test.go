package fapitest_test

import (
	"crypto/x509"
	"testing"

	"github.com/idfoundry/fapigo/fapitest"
)

func TestSelfSignedServerCert(t *testing.T) {
	tlsCert, err := fapitest.SelfSignedServerCert("host.docker.internal", "extra.example.org")
	if err != nil {
		t.Fatalf("SelfSignedServerCert() error = %v", err)
	}
	if len(tlsCert.Certificate) != 1 {
		t.Fatalf("len(Certificate) = %d, want 1", len(tlsCert.Certificate))
	}

	cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatalf("parse generated certificate: %v", err)
	}
	for _, host := range []string{"host.docker.internal", "localhost", "extra.example.org"} {
		if err := cert.VerifyHostname(host); err != nil {
			t.Errorf("VerifyHostname(%q) = %v, want nil", host, err)
		}
	}
	if err := cert.VerifyHostname("127.0.0.1"); err != nil {
		t.Errorf("VerifyHostname(127.0.0.1) = %v, want nil (IP SAN)", err)
	}
	if err := cert.VerifyHostname("unrelated.example.org"); err == nil {
		t.Error("VerifyHostname(unrelated.example.org) = nil, want an error — this host was never listed")
	}

	found := false
	for _, ku := range cert.ExtKeyUsage {
		if ku == x509.ExtKeyUsageServerAuth {
			found = true
		}
	}
	if !found {
		t.Error("certificate does not carry ExtKeyUsageServerAuth")
	}
}

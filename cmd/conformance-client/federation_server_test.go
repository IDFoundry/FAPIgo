package main

import (
	"crypto/x509"
	"testing"
)

func TestSelfSignedServerCertIsUsable(t *testing.T) {
	tlsCert, err := selfSignedServerCert("host.docker.internal")
	if err != nil {
		t.Fatalf("selfSignedServerCert() error = %v", err)
	}
	if len(tlsCert.Certificate) != 1 {
		t.Fatalf("len(Certificate) = %d, want 1", len(tlsCert.Certificate))
	}

	cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatalf("parse generated certificate: %v", err)
	}
	if err := cert.VerifyHostname("host.docker.internal"); err != nil {
		t.Errorf("VerifyHostname(host.docker.internal) = %v, want nil", err)
	}
	if err := cert.VerifyHostname("localhost"); err != nil {
		t.Errorf("VerifyHostname(localhost) = %v, want nil", err)
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

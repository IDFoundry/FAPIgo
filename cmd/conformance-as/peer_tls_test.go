package main

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
)

func TestPeerTLSConfigAcceptsUnverifiedHostRegardlessOfCert(t *testing.T) {
	// No certificate at all — an unverified host still passes, since
	// VerifyConnection returns before ever looking at PeerCertificates.
	cfg := peerTLSConfig(x509.NewCertPool(), []string{"ta.example.org"})
	err := cfg.VerifyConnection(tls.ConnectionState{ServerName: "ta.example.org"})
	if err != nil {
		t.Errorf("VerifyConnection(unverified host, no certs) = %v, want nil", err)
	}
}

func TestPeerTLSConfigMatchesUnverifiedHostCaseInsensitively(t *testing.T) {
	cfg := peerTLSConfig(x509.NewCertPool(), []string{"TA.example.org"})
	err := cfg.VerifyConnection(tls.ConnectionState{ServerName: "ta.example.org"})
	if err != nil {
		t.Errorf("VerifyConnection = %v, want nil (case-insensitive match)", err)
	}
}

func TestPeerTLSConfigVerifiesNonListedHostAgainstPool(t *testing.T) {
	cert, pool := selfSignedCert(t)
	leaf := cert.Leaf

	// The cert's own CommonName/IP SANs are "127.0.0.1" (selfSignedCert's
	// own doc comment) — verifying against that same name, with the
	// matching pool, succeeds.
	err := peerTLSConfig(pool, nil).VerifyConnection(tls.ConnectionState{
		ServerName: "127.0.0.1", PeerCertificates: []*x509.Certificate{leaf},
	})
	if err != nil {
		t.Errorf("VerifyConnection(valid cert, matching pool) = %v, want nil", err)
	}
}

func TestPeerTLSConfigRejectsNonListedHostWithUntrustedCert(t *testing.T) {
	cert, _ := selfSignedCert(t)
	leaf := cert.Leaf
	// An empty pool trusts nothing — the cert this connection actually
	// presented isn't in it.
	err := peerTLSConfig(x509.NewCertPool(), nil).VerifyConnection(tls.ConnectionState{
		ServerName: "127.0.0.1", PeerCertificates: []*x509.Certificate{leaf},
	})
	if err == nil {
		t.Errorf("VerifyConnection(untrusted cert) = nil error, want error")
	}
}

func TestPeerTLSConfigRejectsNoPeerCertificates(t *testing.T) {
	err := peerTLSConfig(x509.NewCertPool(), nil).VerifyConnection(tls.ConnectionState{ServerName: "ta.example.org"})
	if err == nil {
		t.Errorf("VerifyConnection(no peer certificates) = nil error, want error")
	}
}
